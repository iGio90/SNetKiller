var selinuxFd = -1;

function strstr(what, which) {
    return what.indexOf(which) >= 0;
}

function log(what, lowerTag) {
    lowerTag = lowerTag || "";
    Java.performNow(function() {
        Java.use("android.util.Log").e("-SNKiller-" + lowerTag, what.toString())
    });
}

Interceptor.attach(Module.findExportByName(null, 'faccessat'), {
    onEnter: function(args) {
        const path = args[1].readUtf8String();
        log(path, 'faccessat');
        this.path = path;
    },
    onLeave: function(ret) {
        if (
            strstr(this.path, '/data/local') ||
            strstr(this.path, '/system')) {
            log('*filtered*', 'faccessat-ret');
            ret.replace(-1);
        }

        log(ret, 'faccessat-ret');
        return ret;
    }
});

Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        const path = args[0].readUtf8String();
        log(path, 'open');
        this.path = path;

        if (this.path.indexOf('.apk') >= 0) {
            this.path = this.path.replace('root', 'xxxx');
            args[0].writeUtf8String(this.path);
        }
    },
    onLeave: function(ret) {
        log(ret.toString() + ' - ' + this.path, 'open-ret');
        if (this.path === '/sys/fs/selinux/enforce') {
            selinuxFd = parseInt(ret);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function(args) {
        const fd = args[0];
        this.fd = fd;
        this.buf = args[1];
    },
    onLeave: function(ret) {
        if (parseInt(this.fd) === selinuxFd) {
            selinuxFd = -1;
            log('*replacing selinux enforce');
            this.buf.writeU8(1);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'stat64'), {
    onEnter: function(args) {
        const path = args[0].readUtf8String();
        log(path, 'stat64');
    },
    onLeave: function(ret) {
        ret.replace(-1);
    }
});
