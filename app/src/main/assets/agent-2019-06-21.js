function strstr(what, which) {
    return what.indexOf(which) >= 0;
}

function log(what, lowerTag) {
    lowerTag = lowerTag || "";
    Java.performNow(function() {
        Java.use("android.util.Log").e("-SNKiller-" + lowerTag, what)
    });
}

Interceptor.attach(Module.findExportByName(null, 'faccessat'), {
    onEnter: function() {
        const path = this.context.x1.readUtf8String();
        log(path, 'faccessat');
        this.path = path;
    },
    onLeave: function(ret) {
        if (strstr(this.path, '/system/bin') ||
            strstr(this.path, '/system/xbin') ||
            strstr(this.path, '/data/local')) {
            log('*filtered*', 'faccessat-ret');
                ret.replace(-1);
        }

        log(path, 'faccessat-ret');
        return ret;
    }
});

Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function() {
        const path = this.context.x0.readUtf8String();
        log(path, 'open');
        this.path = path;
    },
    onLeave: function(ret) {
        log(ret.toString() + ' - ' + this.path, 'open-ret');
    }
});

Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function() {
        const fd = this.context.x0;
        log(fd, 'read');
        this.fd = fd;
    },
    onLeave: function(ret) {

    }
});

Interceptor.attach(Module.findExportByName(null, 'stat64'), {
    onEnter: function() {
        const path = this.context.x0.readUtf8String();
        log(path, 'stat64');
    }
});
