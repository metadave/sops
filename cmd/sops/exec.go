package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"os/exec"

	"path"

	"go.mozilla.org/sops"
	"go.mozilla.org/sops/cmd/sops/codes"
	"go.mozilla.org/sops/cmd/sops/common"
	"go.mozilla.org/sops/keyservice"
)

type execCmdOpts struct {
	Cipher         sops.Cipher
	InputStore     sops.Store
	OutputStore    sops.Store
	InputPath      string
	IgnoreMAC      bool
	KeyServices    []keyservice.KeyServiceClient
	ShowMasterKeys bool
	EnvName        string
	Cmd            []string
}

type runCmdUntilOkOpts struct {
	TmpFile        *os.File
	OriginalHash   []byte
	InputStore     sops.Store
	ShowMasterKeys bool
	Tree           *sops.Tree
	EnvName        string
	Cmd            []string
}

func execCmd(opts execCmdOpts) ([]byte, error) {
	// Load the file
	tree, err := common.LoadEncryptedFile(opts.InputStore, opts.InputPath)
	if err != nil {
		return nil, err
	}
	// Decrypt the file
	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher: opts.Cipher, IgnoreMac: opts.IgnoreMAC, Tree: tree, KeyServices: opts.KeyServices,
	})
	if err != nil {
		return nil, err
	}

	return execTree(opts, tree, dataKey)
}

func execTree(opts execCmdOpts, tree *sops.Tree, dataKey []byte) ([]byte, error) {
	// Create temporary file for editing
	tmpdir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not create temporary directory: %s", err), codes.CouldNotWriteOutputFile)
	}
	defer os.RemoveAll(tmpdir)
	tmpfile, err := os.Create(path.Join(tmpdir, path.Base(opts.InputPath)))
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not create temporary file: %s", err), codes.CouldNotWriteOutputFile)
	}

	// Write to temporary file
	var out []byte
	if opts.ShowMasterKeys {
		out, err = opts.OutputStore.EmitEncryptedFile(*tree)
	} else {
		out, err = opts.OutputStore.EmitPlainFile(tree.Branches)
	}
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	_, err = tmpfile.Write(out)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not write output file: %s", err), codes.CouldNotWriteOutputFile)
	}

	// Compute file hash to detect if the file has been edited
	origHash, err := hashFile(tmpfile.Name())
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not hash file: %s", err), codes.CouldNotReadInputFile)
	}

	// Let the user edit the file
	err = runCmdUntilOk(runCmdUntilOkOpts{
		InputStore: opts.InputStore, OriginalHash: origHash, TmpFile: tmpfile,
		ShowMasterKeys: opts.ShowMasterKeys, Tree: tree, EnvName: opts.EnvName, Cmd: opts.Cmd})
	if err != nil {
		return nil, err
	}

	// Encrypt the file
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey, Tree: tree, Cipher: opts.Cipher,
	})
	if err != nil {
		return nil, err
	}

	// Output the file
	encryptedFile, err := opts.OutputStore.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	return encryptedFile, nil
}

func runCmdUntilOk(opts runCmdUntilOkOpts) error {
	for {
		//(c string, path string, newenv string
		err := runCmd(opts.Cmd, opts.TmpFile.Name(), opts.EnvName)
		return err
		// if err != nil {
		// 	return common.NewExitError(fmt.Sprintf("Could not run editor: %s", err), codes.NoEditorFound)
		// }
		// newHash, err := hashFile(opts.TmpFile.Name())
		// if err != nil {
		// 	return common.NewExitError(fmt.Sprintf("Could not hash file: %s", err), codes.CouldNotReadInputFile)
		// }
		// if bytes.Equal(newHash, opts.OriginalHash) {
		// 	return common.NewExitError("File has not changed, exiting.", codes.FileHasNotBeenModified)
		// }
		// edited, err := ioutil.ReadFile(opts.TmpFile.Name())
		// if err != nil {
		// 	return common.NewExitError(fmt.Sprintf("Could not read edited file: %s", err), codes.CouldNotReadInputFile)
		// }
		// newBranches, err := opts.InputStore.LoadPlainFile(edited)
		// if err != nil {
		// 	log.WithField(
		// 		"error",
		// 		err,
		// 	).Errorf("Could not load tree, probably due to invalid " +
		// 		"syntax. Press a key to return to the editor, or Ctrl+C to " +
		// 		"exit.")
		// 	bufio.NewReader(os.Stdin).ReadByte()
		// 	continue
		// }
		// if opts.ShowMasterKeys {
		// 	// The file is not actually encrypted, but it contains SOPS
		// 	// metadata
		// 	t, err := opts.InputStore.LoadEncryptedFile(edited)
		// 	if err != nil {
		// 		log.WithField(
		// 			"error",
		// 			err,
		// 		).Errorf("SOPS metadata is invalid. Press a key to " +
		// 			"return to the editor, or Ctrl+C to exit.")
		// 		bufio.NewReader(os.Stdin).ReadByte()
		// 		continue
		// 	}
		// 	// Replace the whole tree, because otherwise newBranches would
		// 	// contain the SOPS metadata
		// 	opts.Tree = &t
		// }
		// opts.Tree.Branches = newBranches
		// needVersionUpdated, err := AIsNewerThanB(version, opts.Tree.Metadata.Version)
		// if err != nil {
		// 	return common.NewExitError(fmt.Sprintf("Failed to compare document version %q with program version %q: %v", opts.Tree.Metadata.Version, version, err), codes.FailedToCompareVersions)
		// }
		// if needVersionUpdated {
		// 	opts.Tree.Metadata.Version = version
		// }
		// if opts.Tree.Metadata.MasterKeyCount() == 0 {
		// 	log.Error("No master keys were provided, so sops can't " +
		// 		"encrypt the file. Press a key to return to the editor, or " +
		// 		"Ctrl+C to exit.")
		// 	bufio.NewReader(os.Stdin).ReadByte()
		// 	continue
		// }
		// break
	}
	return nil
}

func runCmd(c []string, path string, newenv string) error {
	os.Setenv(newenv, path)

	var cmd *exec.Cmd
	cmd = exec.Command(c[0], c[1:]...)
	envVal := fmt.Sprintf("%s=%s", newenv, path)
	cmd.Env = append(os.Environ(), envVal)

	cmdOut, err := cmd.Output()
	fmt.Println(string(cmdOut))
	return err
}

// func lookupAnyEditor(editorNames ...string) (editorPath string, err error) {
// 	for _, editorName := range editorNames {
// 		editorPath, err = exec.LookPath(editorName)
// 		if err == nil {
// 			return editorPath, nil
// 		}
// 	}
// 	return "", fmt.Errorf("no editor available: sops attempts to use the editor defined in the EDITOR environment variable, and if that's not set defaults to any of %s, but none of them could be found", strings.Join(editorNames, ", "))
// }
