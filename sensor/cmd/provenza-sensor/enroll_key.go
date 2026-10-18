// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// keyEnv is read when --key is not given, so the key stays out of argv
// (ps) and out of the shell history.
const keyEnv = "PROVENZA_SENSOR_KEY"

// resolveKey returns the sensor key from, in order: --key (with "-" meaning
// one line on stdin), $PROVENZA_SENSOR_KEY, or a prompt on the terminal
// with echo off. A key typed on the command line lands in the shell history;
// the other three do not.
func resolveKey(flagValue string, stdin *os.File, prompt io.Writer) (string, error) {
	switch {
	case flagValue == "-":
		return readLine(stdin)
	case flagValue != "":
		return strings.TrimSpace(flagValue), nil
	}
	if v := strings.TrimSpace(os.Getenv(keyEnv)); v != "" {
		return v, nil
	}
	if !isTerminal(stdin) {
		return "", errors.New("no key: pass --key - with the key on stdin, set " + keyEnv + ", or run in a terminal to be asked")
	}
	fmt.Fprint(prompt, "Sensor key (from Register sensor on the Runtime page; input hidden): ")
	key, err := readHidden(stdin)
	fmt.Fprintln(prompt)
	return key, err
}

func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read key: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// readHidden reads one line from a terminal with echo turned off, and
// restores the terminal whatever happens.
func readHidden(f *os.File) (string, error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("terminal: %w", err)
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", fmt.Errorf("terminal: %w", err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old) //nolint:errcheck
	return readLine(f)
}
