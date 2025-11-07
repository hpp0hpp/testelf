
// Frida 17 hook for libloader.so AES_decrypt
if (Process.platform === 'linux' || Process.platform === 'android') {
    const libName = 'libcore.so';
    const base = Process.getModuleByName(libName).base;
    // 查找符号地址
    const aesDecryptPtr = base.add(0x2d967c)
    // hook AES_decrypt 函数,onenter添加对0x2d0a3c新的hook,onleave取消hook
    Interceptor.attach(aesDecryptPtr, {
        onEnter: function (args) {
            Interceptor.attach(base.add(0x2d0a3c), {
                onEnter(args) {
                    console.log('called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                    console.log('a1:', hexdump(ptr(args[0]).readPointer(), { offset: 0, length: Math.min(16, args[1].toInt32()), header: true, ansi: true })); // 输出第一个参数的值
                    console.log(args[1]);
                }
            });
        },
        onLeave: function (retval) {
            Interceptor.detachAll();
        }
    });

}

