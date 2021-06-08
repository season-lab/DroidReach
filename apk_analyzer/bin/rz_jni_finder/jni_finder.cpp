#include <cassert>
#include <vector>
#include <stdio.h>
#include <rz_core.h>
#include <rz_list.h>

class Section {
public:
    ut64    addr;
    ut8*    data;
    ut64    size;
    RzCore* core;
    bool    has_code;

    Section(RzBinSection* section, RzCore* core) {
        addr     = section->vaddr;
        size     = section->size;
        has_code = section->perm & RZ_PERM_X;

        data = new ut8[section->size];

        assert(rz_io_read_at_mapped(core->io, section->vaddr, data, section->size));
    }

    ~Section() {
        delete data;
    }

    bool contains(ut64 taddr) {
        return addr <= taddr && taddr < addr + size;
    }

    ut8 read(ut64 taddr) {
        assert (contains(taddr));
        return data[taddr - addr];
    }

    void print() {
        printf("Section @ %#x (%d) [%02x ...]\n", addr, size, data[0]);
    }
};

class AddressSpace {
public:
    std::vector<Section*> sections;

    AddressSpace() {}
    ~AddressSpace() {
        for (Section* s : sections)
            delete s;
    }

    void addSection(Section* s) {
        sections.push_back(s);
    }

    bool contains(ut64 addr) {
        for (Section* s : sections)
            if (s->contains(addr))
                return true;
        return false;
    }

    bool contains_range(ut64 min_addr, ut64 max_addr) {
        assert (max_addr > min_addr);

        for (Section* s : sections) {
            ut64 addr = min_addr;
            for (; addr < max_addr; ++addr)
                if (!s->contains(addr))
                    break;
            if (addr == max_addr)
                return true;
        }
        return false;
    }

    bool points_to_code(ut64 addr) {
        for (Section* s : sections)
            if (s->contains(addr) && s->has_code)
                return true;
        return false;
    }

    ut8 read(ut64 addr) {
        for (Section* s : sections) {
            if (s->contains(addr))
                return s->read(addr);
        }

        assert (0);
    }

    ut32 read_le_32(ut64 addr) {
        return (read(addr + 3) << 24UL) | (read(addr + 2) << 16UL) | (read(addr + 1) << 8UL) | read(addr);
    }
};

static AddressSpace as;

static const RzCmdDescArg args_none[] = {{}};
static const RzCmdDescHelp rz_aJj_help = {
        .summary = "Detect JNI functions",
        .args = args_none
    };

static void init_sections(RzCore* core) {
    static bool g_init_done = false;
    if (g_init_done)
        return;

    RzBinFile *bf = core->bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
    RzList *sections = o ? o->sections : NULL;

    void       * _section;
    RzListIter * iter;
	rz_list_foreach (sections, iter, _section) {
        RzBinSection* section = (RzBinSection*)_section;
        if (section->size == 0 || section->is_segment)
            continue;

        as.addSection(new Section(section, core));
	}

    g_init_done = true;
}

static RzCmdStatus rz_aJj_handler(RzCore *core, int argc, const char **argv) {
    init_sections(core);

    for (Section* s : as.sections) {
        s->print();
    }

    return RZ_CMD_STATUS_OK;
}

static bool rz_aJj_init(RzCore* core) {
    RzCmd* rzcmd = core->rcmd;
    RzCmdDesc *root_cd = rz_cmd_desc_group_new(rzcmd, rz_cmd_get_root(rzcmd), "aJj", rz_aJj_handler, &rz_aJj_help, &rz_aJj_help);
    return true;
}

static RzCorePlugin rz_core_plugin_java_jni_finder = {
    /* .name = */ "JniFinder",
    /* .desc = */ "Plugin for finding JNI functions",
    /* .license = */ "LGPL3",
    /* .author = */ "bageyelet",
    /* .version = */ NULL,
    /*.init = */ rz_aJj_init,
    /*.fini = */ NULL
};

// Public Stuff
extern "C" {
    RZ_API RzLibStruct rizin_plugin = {
        /* .type = */ RZ_LIB_TYPE_CORE,
        /* .data = */ &rz_core_plugin_java_jni_finder,
        /* .version = */ RZ_VERSION,
        /* .free = */ NULL,
        /* .pkgname = */ "rz-Java-jni"
    };

    RZ_API RzLibStruct *rizin_plugin_function(void) {
        RzLibStruct* p = (RzLibStruct*)malloc(sizeof(RzLibStruct));
        memcpy(p, &rizin_plugin, sizeof(RzLibStruct));
        return p;
    }
}
