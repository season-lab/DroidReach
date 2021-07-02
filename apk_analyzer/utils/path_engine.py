import networkx as nx
import claripy

from angr.engines.vex.heavy.heavy import SimStateStorageMixin, VEXMixin, VEXLifter
from angr.engines.vex.claripy.datalayer import ClaripyDataMixin
from cex_src.cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor

class PathEngine(ClaripyDataMixin, SimStateStorageMixin, VEXMixin, VEXLifter):
    def __init__(self, *args, monitor_target=None, **xargs):
        super().__init__(*args, **xargs)

        if self.project.arch.name == "ARMEL":
            self.ret_register  = "r0"
            self.arg1_register = "r0"
            self.arg2_register = "r1"
        elif self.project.arch.name == "AMD64":
            self.ret_register  = "rax"
            self.arg1_register = "rdi"
            self.arg2_register = "rsi"
        else:
            raise Exception("Unsopported arch", self.project.arch.name)

        self.monitor_target = monitor_target

    def _find_register_name(self, offset):
        for r in self.project.arch.register_list:
            if r.vex_offset == offset and r.size == self.project.arch.bytes:
                return r.name
        return None

    def _process_block(self, irsb):
        if self.has_model(irsb.addr):
            self.handle_model(irsb.addr)
            return

        self.state.history.recent_block_count = 1
        self.state.scratch.guard = claripy.true
        self.state.scratch.sim_procedure = None
        self.state.scratch.bbl_addr = irsb.addr
        self.state.scratch.set_tyenv(irsb.tyenv)
        self.state.scratch.irsb = irsb

        self.handle_vex_block(irsb)

    def _perform_vex_stmt_Exit(self, guard, target, jumpkind):
        # print("Exit:", guard, target, jumpkind)
        if self.monitor_target is not None:
            self.monitor_target(target)

    def _perform_vex_defaultexit(self, expr, jumpkind):
        # print("default exit:", expr)
        if self.monitor_target is not None:
            self.monitor_target(expr)

    def process_path(self, state, path):
        self.state = state.copy()

        for bb, size in path:
            block = self.project.factory.block(bb, size=size if size > 0 else None)
            proc_size = 0
            while 1:
                block.vex # It will shrink the block size according to VEX (dont remove it!)
                block_size = block.size
                # print("processing block:")
                # block.pp()
                # block.vex.pp()
                self._process_block(block.vex)
                proc_size += block_size
                if proc_size >= size:
                    break
                block = self.project.factory.block(bb + proc_size, size=size - proc_size)

        return self.state

    def _find_symbol_at(self, addr):
        symb = self.project.loader.find_symbol(addr)
        if symb is None:
            name = self.project.loader.find_plt_stub_name(addr)
            if name is None:
                return None
        else:
            name = symb.name
        return name

    def has_model(self, addr):
        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(self.project, addr):
            addr += 1

        name = self._find_symbol_at(addr)
        if name is None:
            return False

        handler_name = f"handle_function_{name}"
        if hasattr(self, handler_name):
            return True
        return False

    def handle_model(self, addr):
        assert self.has_model(addr)
        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(self.project, addr):
            addr += 1

        name = self._find_symbol_at(addr)
        handler_name = f"handle_function_{name}"
        return getattr(self, handler_name)()

    def _set_return_value(self, val):
        setattr(self.state.regs, self.ret_register, val)

    def _get_arg1(self):
        return getattr(self.state.regs, self.arg1_register)

    def handle_function_malloc(self):
        self._set_return_value(self.state.heap.allocate(self._get_arg1()))

    def handle_function__Znwm(self):
        self._set_return_value(self.state.heap.allocate(self._get_arg1()))

    def handle_function__Znwj(self):
        self._set_return_value(self.state.heap.allocate(self._get_arg1()))

MAX_DEPTH             = 10
MAX_PATH_PER_FUNCTION = 10

def generate_paths(cex_proj, engine, entry):
    cg  = cex_proj.get_callgraph(entry)

    def compose_with_empty(it):
        yield []
        for el in it:
            yield el

    def mix(*its):
        els = list(map(next, its))
        yield els

        i = 0
        while i < MAX_PATH_PER_FUNCTION:
            i += 1

            has_els = False
            for i, it in enumerate(its):
                try:
                    n = next(it)
                except StopIteration:
                    continue

                has_els = True
                els[i] = n
                yield els

            if not has_els:
                break

    def find_ret_blocks(cfg, addr):
        ret_sites  = set(cg.nodes[addr]["data"].return_sites)
        ret_blocks = set()
        for bb in cfg.nodes:
            data = cfg.nodes[bb]["data"]
            for insn in data.insns:
                if insn.addr in ret_sites:
                    ret_blocks.add(bb)
        return ret_blocks

    def get_block_length(cfg, addr):
        l = 0
        for insn in cfg.nodes[addr]["data"].insns:
            l += insn.size
        return l

    def find_path_recursive(addr, rec_idx=0):
        if rec_idx > MAX_DEPTH:
            return

        cfg = cex_proj.get_cfg(addr)
        addr_f = addr
        if cfg.nodes[addr]["data"].is_thumb:
            addr_f += 1
        for ret_bb in find_ret_blocks(cfg, addr):
            if addr == ret_bb:
                # one with fallthrough, and one without
                if len(cfg.nodes[addr]["data"].calls) > 0:
                    assert len(cfg.nodes[addr]["data"].calls) == 1
                    target = cfg.nodes[addr]["data"].calls[0]
                    if engine.has_model(target):
                        yield [(addr_f, get_block_length(cfg, addr)), (target, 0)]
                    else:
                        yield [(addr_f, get_block_length(cfg, addr))]
                        for rec_path in find_path_recursive(cfg.nodes[addr]["data"].calls[0], rec_idx+1):
                            yield [(addr_f, get_block_length(cfg, addr))] + rec_path
                else:
                    yield [(addr_f, get_block_length(cfg, addr))]

            for path in nx.all_simple_paths(cfg, addr, ret_bb):
                complete_path       = list()
                rec_paths_iterators = list()
                for bb in path:
                    if len(cfg.nodes[bb]["data"].calls) > 0:
                        assert len(cfg.nodes[bb]["data"].calls) == 1
                        target = cfg.nodes[bb]["data"].calls[0]
                        if engine.has_model(target):
                            # If the target function is a model, we do not want to avoid the call
                            # moreover, we do not want to explore the code if it is not a stub!
                            rec_paths_iterators.append([[(target, 0)]].__iter__())
                        else:
                            rec_paths_iterators.append(
                                compose_with_empty(find_path_recursive(cfg.nodes[bb]["data"].calls[0], rec_idx+1)))

                # mix the elements and take some paths. This should be the cartesian product
                # we are pruning some path
                for rec_paths in mix(*rec_paths_iterators):
                    i = 0
                    for bb in path:
                        orig_bb = bb
                        if cfg.nodes[bb]["data"].is_thumb:
                            bb += 1

                        complete_path.append((bb, get_block_length(cfg, orig_bb)))
                        if len(cfg.nodes[orig_bb]["data"].calls) > 0:
                            complete_path += rec_paths[i]
                            i += 1

                    yield complete_path
                    complete_path = list()

    for p in find_path_recursive(entry):
        yield p
