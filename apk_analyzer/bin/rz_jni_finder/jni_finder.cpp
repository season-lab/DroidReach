#include <algorithm>
#include <cassert>
#include <vector>
#include <string>
#include <stdio.h>
#include <rz_core.h>
#include <rz_list.h>

#define is_ascii(v) ((v) >= 32 && (v) <= 126)

struct JNINativeMethod {
    const char * name;
    const char * signature;
    void * fnPtr;
};

class Section {
public:
    char* name;
    ut64  addr;
    ut8*  data;
    ut64  size;
    bool  has_code;
    bool  is_readable;

    Section(RzBinSection* section, RzCore* core) {
        addr        = section->vaddr;
        size        = section->size;
        name        = section->name;
        has_code    = section->perm & RZ_PERM_X;
        is_readable = section->perm & RZ_PERM_R;

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

    ut8* ptr_to(ut64 taddr, ut64* rem_size) {
        if (!contains(taddr))
            return NULL;

        *rem_size = addr + size - taddr;
        return &data[taddr - addr];
    }

    void print() {
        printf("Section %s @ %#llx (%lld) [%02x ...]\n", name, addr, size, data[0]);
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

    ut8* ptr_to(ut64 addr, ut64* rem_size) {
        for (Section* s : sections) {
            if (s->contains(addr))
                return s->ptr_to(addr, rem_size);
        }

        return NULL;
    }

    ut32 read_le_32(ut64 addr) {
        return (read(addr + 3) << 24UL) | (read(addr + 2) << 16UL) | (read(addr + 1) << 8UL) | read(addr);
    }

    const char* read_string(ut64 addr) {
        static const ut64 g_max_len = 256;

        ut64 rem_size;
        ut8* s = ptr_to(addr, &rem_size);
        if (!s)
            return NULL;

        ut64 i = 0;
        while (i < std::min(g_max_len, rem_size)) {
            if (!s[i])
                break;
            if (!is_ascii(s[i]))
                return NULL;

            ++i;
        }

        if (i > 0)
            return (const char*)s;
        return NULL;
    }
};

static AddressSpace as;
static std::vector<JNINativeMethod> jni_methods;

static const RzCmdDescArg args_none[] = {{}};
static const RzCmdDescHelp rz_aJJ_help = {
        .summary = "Detect JNI functions",
        .args = args_none
    };
static const RzCmdDescHelp rz_aJJj_help = {
        .summary = "Detect JNI functions (json)",
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

static void init_jni_methods(RzCore* core) {
    static bool g_init_done = false;
    if (g_init_done)
        return;

    init_sections(core);

    for (Section* s : as.sections) {
        if (s->has_code || !s->is_readable)
            continue;

        for (ut64 addr = s->addr; addr < s->addr + s->size - 12; ++addr) {
            ut64 method_ptr = as.read_le_32(addr);
            ut64 args_ptr   = as.read_le_32(addr + 4);
            ut64 fun_ptr    = as.read_le_32(addr + 8);

            if (!as.points_to_code(fun_ptr))
                continue;

            if (!as.contains(method_ptr))
                continue;

            if (!as.contains(args_ptr))
                continue;

            const char* method_name = as.read_string(method_ptr);
            if (method_name == NULL)
                continue;

            const char* args = as.read_string(args_ptr);
            if (args == NULL)
                continue;

            if (args[0] != '(' || !strchr(args, ')'))
                continue;

            JNINativeMethod m = {
                .name = method_name,
                .signature = args,
                .fnPtr = (void*)fun_ptr
            };

            jni_methods.push_back(m);
        }
    }

    g_init_done = true;
}

static RzCmdStatus rz_aJJ_handler(RzCore *core, int argc, const char **argv) {
    init_jni_methods(core);

    puts("dynamic JNI:");
    for (JNINativeMethod& m : jni_methods) {
        printf("%s, %s, %p\n", m.name, m.signature, m.fnPtr);
    }
    return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_aJJj_handler(RzCore *core, int argc, const char **argv) {
    init_jni_methods(core);

    PJ *pj = NULL;
    pj = pj_new();

    pj_a(pj);
    for (JNINativeMethod& m : jni_methods) {
        pj_o(pj);
        pj_ks(pj, "name", m.name);
        pj_ks(pj, "signature", m.signature);
        pj_kn(pj, "fnPtr", (ut64)m.fnPtr);
        pj_end(pj);
    }
    pj_end(pj);

    rz_cons_println(pj_string(pj));
    pj_free(pj);
    return RZ_CMD_STATUS_OK;
}

static bool rz_aJJ_init(RzCore* core) {
    RzCmd* rzcmd = core->rcmd;
    RzCmdDesc *root_cd = rz_cmd_desc_group_new(rzcmd, rz_cmd_get_root(rzcmd), "aJJ", rz_aJJ_handler, &rz_aJJ_help, &rz_aJJ_help);
    rz_cmd_desc_argv_new(rzcmd, root_cd, "aJJj", rz_aJJj_handler, &rz_aJJj_help);
    return true;
}

static RzCorePlugin rz_core_plugin_java_jni_finder = {
    /* .name = */ "JniFinder",
    /* .desc = */ "Plugin for finding JNI functions",
    /* .license = */ "LGPL3",
    /* .author = */ "bageyelet",
    /* .version = */ NULL,
    /*.init = */ rz_aJJ_init,
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
