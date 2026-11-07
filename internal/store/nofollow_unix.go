//go:build unix

package store

import "syscall"

const openNoFollowFlag = syscall.O_NOFOLLOW
