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
	"encoding/json"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
)

type ModuleCommand struct {
	Command string `json:"command"`
	Name    string `json:"name"`
	Code    []byte `json:"code"`
}

var _commands = []*cli.Command{
	{
		Name:    "load",
		Usage:   "Loads a wasm module to the kernel",
		Aliases: []string{"l"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "name",
				Usage: "name of the loaded module",
			},
		},
		ArgsUsage: "load wasm from `FILE`",
		Action: func(ctx *cli.Context) error {
			if ctx.Args().Len() < 1 {
				log.Fatal("filename required")
			}

			filename := ctx.Args().First()
			code, err := ioutil.ReadFile(filename)
			if err != nil {
				return err
			}

			name := ctx.String("name")
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
		Name:    "reset",
		Usage:   "reset the wasm vm in the kernel",
		Aliases: []string{"r"},
		Action: func(ctx *cli.Context) error {
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
	app := &cli.App{
		Name:     "w3k",
		Usage:    "cli to control the wasm kernel module",
		Commands: _commands,
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
