/*
 * The MIT License (MIT)
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	cli "github.com/cristalhq/acmd"
)

type ModuleCommand struct {
	Command string `json:"command"`
	Name    string `json:"name"`
	Code    []byte `json:"code"`
}

type loadFlags struct {
	File string
	Name string
}

func (c *loadFlags) Flags() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.StringVar(&c.File, "file", "my-module.wasm", "the file path of the loaded Wasm module")
	fs.StringVar(&c.Name, "name", "my-module", "how to name the loaded Wasm module")
	return fs
}

var cmds = []cli.Command{
	{
		Name:        "load",
		Description: "loads a Wasm module to the kernel",
		Alias:       "l",
		FlagSet:     &loadFlags{},
		ExecFunc: func(ctx context.Context, args []string) error {
			if len(args) < 1 {
				log.Fatal("filename required")
			}

			var cfg loadFlags
			if err := cfg.Flags().Parse(args); err != nil {
				return err
			}

			filename := cfg.File
			code, err := ioutil.ReadFile(filename)
			if err != nil {
				return err
			}

			name := cfg.Name
			if name == "" {
				basename := filepath.Base(filename)
				name = strings.TrimSuffix(basename, filepath.Ext(basename))
			}

			c := ModuleCommand{
				Command: "load",
				Name:    name,
				Code:    code,
			}

			return sendCommand(c)
		},
	},
	{
		Name:        "reset",
		Description: "reset the wasm vm in the kernel",
		Alias:       "r",
		ExecFunc: func(ctx context.Context, args []string) error {
			c := ModuleCommand{
				Command: "reset",
			}

			return sendCommand(c)
		},
	},
}

func sendCommand(c ModuleCommand) error {
	j, err := json.Marshal(c)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("/dev/wasm", j, fs.ModeDevice)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	r := cli.RunnerOf(cmds, cli.Config{
		AppName:        "w3k",
		AppDescription: "cli to control the wasm kernel module",
	})
	if err := r.Run(); err != nil {
		log.Fatal(err)
	}
}
