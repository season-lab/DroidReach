function isModuleInitialized(libname) {
    try {
        Module.ensureInitialized(libname);
    } catch (err) {
        return false;
    }
    return true;
}

function buildModuleMap() {
    Process.enumerateModules({
        onMatch: function(module){
            module_map[module.name] = module;
        }, 
        onComplete: function(){}
    });
}

function instrumentLibrary(libname) {
    if (modules_info[libname].instrumented)
        return;
    modules_info[libname].instrumented = true;
    modules_info[libname].path = module_map[libname].path;
    modules_info[libname].base = module_map[libname].base.toInt32();

    console.log("instrumenting " + libname + "...");
    var n_functions = 0;
    Module.enumerateExports(libname, {
        onMatch: function(e) {
            if (e.type == 'function') {
                n_functions += 1;
                modules_info[libname].functions[e.name] = {};
                modules_info[libname].functions[e.name].offset    = e.address.toInt32() - modules_info[libname].base;
                modules_info[libname].functions[e.name].n_called  = 0;
                modules_info[libname].functions[e.name].backtrace = 0;

                try {
                    Interceptor.attach(e.address, {
                        onEnter(args) {
                            // console.log("[ " +  libname + " ] : " + e.name + " called");
                            // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                            //                   .map(DebugSymbol.fromAddress).join('\n'));

                            modules_info[libname].functions[e.name].n_called += 1;
                            if (modules_info[libname].functions[e.name].backtrace == "") {
                                // keep only a single backtrace
                                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE) // Backtracer.FUZZY
                                                    .map(DebugSymbol.fromAddress).join('\n');
                                modules_info[libname].functions[e.name].backtrace = backtrace;
                            }
                        }
                    });
                } catch (err) {
                    console.log("Unable to intercept function " + e.name + " @ " + e.address);
                }
            }
        },
        onComplete: function() {
            console.log("instrumented " + n_functions + " functions");
        }
    });
}

// [ "liba.so", "libb.so", ... ]
var modules      = $$MODULES$$;
var modules_info = {};
var module_map   = {};

buildModuleMap();
modules.forEach(
    libname => {
        modules_info[libname] = {
            instrumented: false,
            functions:    {},
            path:         "",
            base:         0,
        };
        if (isModuleInitialized(libname)) {
            console.log("module " + libname + " found loaded at startup");
            instrumentLibrary(libname);
        }
    });

Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function (args) {
        this.path = Memory.readUtf8String(args[0]);
        console.log("dlopen(" + this.path + ")");
    },
    onLeave: function (retval) {
        if (!retval.isNull() && this.path in modules) {
            instrumentLibrary(this.path);
        }
    }
});

rpc.exports = {
    modinfo() {
        var data = "";
        Object.keys(modules_info).forEach(
            libname => {
                if (libname in module_map) {
                    data += libname + " (" + module_map[libname].path + ") :\n";
                    Object.keys(modules_info[libname].functions).forEach(
                        fname => {
                            var fdata = modules_info[libname].functions[fname];
                            if (fdata.n_called > 0) {
                                data += " - " + fname + " [0x" + fdata.offset.toString(16) + "]"
                                data += " called " + fdata.n_called + " times:\n"
                                data += fdata.backtrace + "\n\n";
                            }
                        }
                    )
                }
            });
        return data;
    }
};
