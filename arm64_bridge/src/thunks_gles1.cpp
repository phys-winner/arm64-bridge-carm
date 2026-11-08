#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"

#include <GLES/gl.h>
#include <android/log.h>

#include <cstdint>

#define LOG_TAG "Arm32Bridge_GLES1"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
using Jit = Dynarmic::A32::Jit;

const void* GuestArray(DynarmicHost& host, uint32_t address, size_t size) {
    if (!address) return nullptr;
    if (address < 0x00100000u) return reinterpret_cast<const void*>(static_cast<uintptr_t>(address));
    return size ? GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, size)
                : GuestToHost(host.GetGuestMemoryBase(), address);
}

}  // namespace

void RegisterGles1Thunks(ThunkManager& manager) {
    manager.RegisterThunk("glAlphaFunc", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glAlphaFunc(static_cast<GLenum>(args.U32()), args.F32());
    });
    manager.RegisterThunk("glBufferSubData", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLintptr offset = static_cast<GLintptr>(args.I32());
        const GLsizeiptr size = static_cast<GLsizeiptr>(args.I32());
        const void* data = GuestArray(host, args.Ptr(), size > 0 ? static_cast<size_t>(size) : 0);
        if (size <= 0 || data) glBufferSubData(target, offset, size, data);
    });
    manager.RegisterThunk("glClientActiveTexture", [](Jit& jit, DynarmicHost&) {
        glClientActiveTexture(static_cast<GLenum>(jit.Regs()[0]));
    });
    manager.RegisterThunk("glColor4f", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glColor4f(args.F32(), args.F32(), args.F32(), args.F32());
    });
    manager.RegisterThunk("glColorPointer", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLint size = static_cast<GLint>(args.I32());
        const GLenum type = static_cast<GLenum>(args.U32());
        const GLsizei stride = static_cast<GLsizei>(args.I32());
        glColorPointer(size, type, stride, GuestArray(host, args.Ptr(), 0));
    });
    manager.RegisterThunk("glDisableClientState", [](Jit& jit, DynarmicHost&) {
        glDisableClientState(static_cast<GLenum>(jit.Regs()[0]));
    });
    manager.RegisterThunk("glEnableClientState", [](Jit& jit, DynarmicHost&) {
        glEnableClientState(static_cast<GLenum>(jit.Regs()[0]));
    });
    manager.RegisterThunk("glFogf", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glFogf(static_cast<GLenum>(args.U32()), args.F32());
    });
    manager.RegisterThunk("glFogfv", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glFogfv(static_cast<GLenum>(args.U32()), static_cast<const GLfloat*>(GuestArray(host, args.Ptr(), 4 * sizeof(GLfloat))));
    });
    manager.RegisterThunk("glLightModelfv", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glLightModelfv(static_cast<GLenum>(args.U32()), static_cast<const GLfloat*>(GuestArray(host, args.Ptr(), 4 * sizeof(GLfloat))));
    });
    manager.RegisterThunk("glLightfv", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glLightfv(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), static_cast<const GLfloat*>(GuestArray(host, args.Ptr(), 4 * sizeof(GLfloat))));
    });
    manager.RegisterThunk("glLoadIdentity", [](Jit&, DynarmicHost&) { glLoadIdentity(); });
    manager.RegisterThunk("glLoadMatrixf", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glLoadMatrixf(static_cast<const GLfloat*>(GuestArray(host, args.Ptr(), 16 * sizeof(GLfloat))));
    });
    manager.RegisterThunk("glMaterialf", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glMaterialf(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), args.F32());
    });
    manager.RegisterThunk("glMaterialfv", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glMaterialfv(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), static_cast<const GLfloat*>(GuestArray(host, args.Ptr(), 4 * sizeof(GLfloat))));
    });
    manager.RegisterThunk("glMatrixMode", [](Jit& jit, DynarmicHost&) {
        glMatrixMode(static_cast<GLenum>(jit.Regs()[0]));
    });
    manager.RegisterThunk("glNormalPointer", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glNormalPointer(static_cast<GLenum>(args.U32()), static_cast<GLsizei>(args.I32()), GuestArray(host, args.Ptr(), 0));
    });
    manager.RegisterThunk("glPushMatrix", [](Jit&, DynarmicHost&) { glPushMatrix(); });
    manager.RegisterThunk("glScalef", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glScalef(args.F32(), args.F32(), args.F32());
    });
    manager.RegisterThunk("glTexCoordPointer", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glTexCoordPointer(static_cast<GLint>(args.I32()), static_cast<GLenum>(args.U32()), static_cast<GLsizei>(args.I32()), GuestArray(host, args.Ptr(), 0));
    });
    manager.RegisterThunk("glTexEnvf", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glTexEnvf(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), args.F32());
    });
    manager.RegisterThunk("glTexEnvfv", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glTexEnvfv(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), static_cast<const GLfloat*>(GuestArray(host, args.Ptr(), 4 * sizeof(GLfloat))));
    });
    manager.RegisterThunk("glTexEnvi", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glTexEnvi(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), static_cast<GLint>(args.I32()));
    });
    manager.RegisterThunk("glTexParameterx", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glTexParameterx(static_cast<GLenum>(args.U32()), static_cast<GLenum>(args.U32()), static_cast<GLfixed>(args.I32()));
    });
    manager.RegisterThunk("glTexSubImage2D", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        const GLenum target = static_cast<GLenum>(args.U32());
        const GLint level = static_cast<GLint>(args.I32());
        const GLint xoffset = static_cast<GLint>(args.I32());
        const GLint yoffset = static_cast<GLint>(args.I32());
        const GLsizei width = static_cast<GLsizei>(args.I32());
        const GLsizei height = static_cast<GLsizei>(args.I32());
        const GLenum format = static_cast<GLenum>(args.U32());
        const GLenum type = static_cast<GLenum>(args.U32());
        glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, GuestArray(host, args.Ptr(), 0));
    });
    manager.RegisterThunk("glTranslatef", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glTranslatef(args.F32(), args.F32(), args.F32());
    });
    manager.RegisterThunk("glVertexPointer", [](Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host.GetGuestMemoryBase());
        glVertexPointer(static_cast<GLint>(args.I32()), static_cast<GLenum>(args.U32()), static_cast<GLsizei>(args.I32()), GuestArray(host, args.Ptr(), 0));
    });
}
