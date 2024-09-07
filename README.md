# Python灰帽子书籍实践项目

虽然书比较老已经20多年了..., 但是里面的技术没有过时, 可以学习逆向技巧,
需要注意一些Api已经变更,比如Python2是默认ASCII码, Python3变成Unicode了

[OpenRCE](https://github.com/OpenRCE)

## Win32 Api
### ThreadContext

* 线程上下文结构体:
  * [WOW64CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-wow64_context): x86
  * [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context): x64

* 获取线程上下文:
  * [Wow64GetThreadContext](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/winbase/nf-winbase-wow64getthreadcontext.md): x86
  * [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext): x64

* 设置线程上下文
  * [Wow64SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64setthreadcontext): x86
  * [SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext): x64