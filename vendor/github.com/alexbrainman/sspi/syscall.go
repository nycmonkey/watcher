// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package sspi

import (
	"syscall"
)

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output zsyscall_windows.go syscall.go

const (
	SEC_E_OK = syscall.Errno(0)

	SEC_I_COMPLETE_AND_CONTINUE = syscall.Errno(590612)
	SEC_I_COMPLETE_NEEDED       = syscall.Errno(590611)
	SEC_I_CONTINUE_NEEDED       = syscall.Errno(590610)

	SEC_E_CONTEXT_EXPIRED    = syscall.Errno(0x80090317) // not sure if the value is valid
	SEC_E_INCOMPLETE_MESSAGE = syscall.Errno(0x80090318)

	NTLMSP_NAME             = "NTLM"
	MICROSOFT_KERBEROS_NAME = "Kerberos"
	NEGOSSP_NAME            = "Negotiate"
	UNISP_NAME              = "Microsoft Unified Security Protocol Provider"
)

type SecPkgInfo struct {
	Capabilities uint32
	Version      uint16
	RPCID        uint16
	MaxToken     uint32
	Name         *uint16
	Comment      *uint16
}

//sys	QuerySecurityPackageInfo(pkgname *uint16, pkginfo **SecPkgInfo) (ret syscall.Errno) = secur32.QuerySecurityPackageInfoW
//sys	FreeContextBuffer(buf *byte) (ret syscall.Errno) = secur32.FreeContextBuffer

const (
	SECPKG_CRED_INBOUND  = 1
	SECPKG_CRED_OUTBOUND = 2
	SECPKG_CRED_BOTH     = (SECPKG_CRED_OUTBOUND | SECPKG_CRED_INBOUND)
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type CredHandle struct {
	Lower uintptr
	Upper uintptr
}

//sys	AcquireCredentialsHandle(principal *uint16, pkgname *uint16, creduse uint32, logonid *LUID, authdata *byte, getkeyfn uintptr, getkeyarg uintptr, handle *CredHandle, expiry *syscall.Filetime) (ret syscall.Errno) = secur32.AcquireCredentialsHandleW
//sys	FreeCredentialsHandle(handle *CredHandle) (ret syscall.Errno) = secur32.FreeCredentialsHandle

const (
	SECURITY_NATIVE_DREP = 16

	SECBUFFER_DATA           = 1
	SECBUFFER_TOKEN          = 2
	SECBUFFER_PKG_PARAMS     = 3
	SECBUFFER_MISSING        = 4
	SECBUFFER_EXTRA          = 5
	SECBUFFER_STREAM_TRAILER = 6
	SECBUFFER_STREAM_HEADER  = 7
	SECBUFFER_PADDING        = 9
	SECBUFFER_STREAM         = 10
	SECBUFFER_READONLY       = 0x80000000
	SECBUFFER_ATTRMASK       = 0xf0000000
	SECBUFFER_VERSION        = 0
	SECBUFFER_EMPTY          = 0

	ISC_REQ_DELEGATE               = 1
	ISC_REQ_MUTUAL_AUTH            = 2
	ISC_REQ_REPLAY_DETECT          = 4
	ISC_REQ_SEQUENCE_DETECT        = 8
	ISC_REQ_CONFIDENTIALITY        = 16
	ISC_REQ_USE_SESSION_KEY        = 32
	ISC_REQ_PROMPT_FOR_CREDS       = 64
	ISC_REQ_USE_SUPPLIED_CREDS     = 128
	ISC_REQ_ALLOCATE_MEMORY        = 256
	ISC_REQ_USE_DCE_STYLE          = 512
	ISC_REQ_DATAGRAM               = 1024
	ISC_REQ_CONNECTION             = 2048
	ISC_REQ_EXTENDED_ERROR         = 16384
	ISC_REQ_STREAM                 = 32768
	ISC_REQ_INTEGRITY              = 65536
	ISC_REQ_MANUAL_CRED_VALIDATION = 524288
	ISC_REQ_HTTP                   = 268435456

	ASC_REQ_DELEGATE        = 1
	ASC_REQ_MUTUAL_AUTH     = 2
	ASC_REQ_REPLAY_DETECT   = 4
	ASC_REQ_SEQUENCE_DETECT = 8
	ASC_REQ_CONFIDENTIALITY = 16
	ASC_REQ_USE_SESSION_KEY = 32
	ASC_REQ_ALLOCATE_MEMORY = 256
	ASC_REQ_USE_DCE_STYLE   = 512
	ASC_REQ_DATAGRAM        = 1024
	ASC_REQ_CONNECTION      = 2048
	ASC_REQ_EXTENDED_ERROR  = 32768
	ASC_REQ_STREAM          = 65536
	ASC_REQ_INTEGRITY       = 131072
)

type CtxtHandle struct {
	Lower uintptr
	Upper uintptr
}

type SecBuffer struct {
	BufferSize uint32
	BufferType uint32
	Buffer     *byte
}

type SecBufferDesc struct {
	Version      uint32
	BuffersCount uint32
	Buffers      *SecBuffer
}

//sys	InitializeSecurityContext(credential *CredHandle, context *CtxtHandle, targname *uint16, contextreq uint32, reserved1 uint32, targdatarep uint32, input *SecBufferDesc, reserved2 uint32, newcontext *CtxtHandle, output *SecBufferDesc, contextattr *uint32, expiry *syscall.Filetime) (ret syscall.Errno) = secur32.InitializeSecurityContextW
//sys	AcceptSecurityContext(credential *CredHandle, context *CtxtHandle, input *SecBufferDesc, contextreq uint32, targdatarep uint32, newcontext *CtxtHandle, output *SecBufferDesc, contextattr *uint32, expiry *syscall.Filetime) (ret syscall.Errno) = secur32.AcceptSecurityContext
//sys	CompleteAuthToken(context *CtxtHandle, token *SecBufferDesc) (ret syscall.Errno) = secur32.CompleteAuthToken
//sys	DeleteSecurityContext(context *CtxtHandle) (ret syscall.Errno) = secur32.DeleteSecurityContext
//sys	ImpersonateSecurityContext(context *CtxtHandle) (ret syscall.Errno) = secur32.ImpersonateSecurityContext
//sys	RevertSecurityContext(context *CtxtHandle) (ret syscall.Errno) = secur32.RevertSecurityContext
//sys	QueryContextAttributes(context *CtxtHandle, attribute uint32, buf *byte) (ret syscall.Errno) = secur32.QueryContextAttributesW
//sys	EncryptMessage(context *CtxtHandle, qop uint32, message *SecBufferDesc, messageseqno uint32) (ret syscall.Errno) = secur32.EncryptMessage
//sys	DecryptMessage(context *CtxtHandle, message *SecBufferDesc, messageseqno uint32, qop *uint32) (ret syscall.Errno) = secur32.DecryptMessage
//sys	ApplyControlToken(context *CtxtHandle, input *SecBufferDesc) (ret syscall.Errno) = secur32.ApplyControlToken
