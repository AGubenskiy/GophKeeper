param(
    [string[]]$Path = @("cmd", "internal", "migrations")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot "..")).Path
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("gophkeeper-doccheck-" + [System.Guid]::NewGuid().ToString("N"))
$checkerPath = Join-Path $tempDir "main.go"

$checkerSource = @'
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type finding struct {
	pos token.Position
	msg string
}

func main() {
	roots := os.Args[1:]
	if len(roots) == 0 {
		roots = []string{"cmd", "internal", "migrations"}
	}

	fset := token.NewFileSet()
	var files []*ast.File
	var findings []finding

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case ".git", ".tools", "dist", "doc", "vendor":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				findings = append(findings, finding{pos: token.Position{Filename: path}, msg: err.Error()})
				return nil
			}
			files = append(files, file)
			findings = append(findings, checkFile(fset, file)...)
			return nil
		})
		if err != nil {
			findings = append(findings, finding{pos: token.Position{Filename: root}, msg: err.Error()})
		}
	}

	packages := map[string]*ast.File{}
	for _, file := range files {
		dir := filepath.Dir(fset.Position(file.Package).Filename)
		key := dir + "\x00" + file.Name.Name
		if packages[key] == nil || hasPackageDoc(file) {
			packages[key] = file
		}
	}
	for _, file := range packages {
		finding := checkPackageDoc(fset, file)
		if finding.msg != "" {
			findings = append(findings, finding)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i].pos, findings[j].pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})

	for _, finding := range findings {
		fmt.Fprintf(os.Stderr, "%s:%d:%d: %s\n", finding.pos.Filename, finding.pos.Line, finding.pos.Column, finding.msg)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}

func checkPackageDoc(fset *token.FileSet, file *ast.File) finding {
	doc := docText(file.Doc)
	name := file.Name.Name
	if name == "main" {
		if strings.HasPrefix(doc, "Command ") {
			return finding{}
		}
		return finding{pos: fset.Position(file.Package), msg: "command package must have a doc comment starting with Command"}
	}
	if strings.HasPrefix(doc, "Package "+name) {
		return finding{}
	}
	return finding{pos: fset.Position(file.Package), msg: "package doc comment must start with Package " + name}
}

func checkFile(fset *token.FileSet, file *ast.File) []finding {
	var findings []finding
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			name := decl.Name.Name
			if !ast.IsExported(name) || !exportedReceiver(decl) {
				continue
			}
			if !commentStartsWith(docText(decl.Doc), name) {
				findings = append(findings, finding{pos: fset.Position(decl.Name.Pos()), msg: "exported function or method " + name + " must have a doc comment starting with its name"})
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					name := spec.Name.Name
					if ast.IsExported(name) && !commentStartsWith(docText(firstDoc(spec.Doc, decl.Doc)), name) {
						findings = append(findings, finding{pos: fset.Position(spec.Name.Pos()), msg: "exported type " + name + " must have a doc comment starting with its name"})
					}
				case *ast.ValueSpec:
					for _, ident := range spec.Names {
						name := ident.Name
						if ast.IsExported(name) && !commentStartsWith(docText(firstDoc(spec.Doc, decl.Doc)), name) {
							findings = append(findings, finding{pos: fset.Position(ident.Pos()), msg: "exported value " + name + " must have a doc comment starting with its name"})
						}
					}
				}
			}
		}
	}
	return findings
}

func hasPackageDoc(file *ast.File) bool {
	return strings.TrimSpace(docText(file.Doc)) != ""
}

func exportedReceiver(decl *ast.FuncDecl) bool {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return true
	}
	expr := decl.Recv.List[0].Type
	for {
		switch typed := expr.(type) {
		case *ast.StarExpr:
			expr = typed.X
		case *ast.Ident:
			return ast.IsExported(typed.Name)
		case *ast.IndexExpr:
			expr = typed.X
		case *ast.IndexListExpr:
			expr = typed.X
		default:
			return false
		}
	}
}

func firstDoc(primary, fallback *ast.CommentGroup) *ast.CommentGroup {
	if primary != nil {
		return primary
	}
	return fallback
}

func docText(group *ast.CommentGroup) string {
	if group == nil {
		return ""
	}
	return strings.TrimSpace(group.Text())
}

func commentStartsWith(doc, name string) bool {
	if doc == "" {
		return false
	}
	if doc == name {
		return true
	}
	if !strings.HasPrefix(doc, name) {
		return false
	}
	if len(doc) == len(name) {
		return true
	}
	r, _ := utf8Rune(doc[len(name):])
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
}

func utf8Rune(value string) (rune, int) {
	for _, r := range value {
		return r, len(string(r))
	}
	return 0, 0
}
'@

try {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Set-Content -LiteralPath $checkerPath -Value $checkerSource -Encoding ascii
    Push-Location $repoRoot
    try {
        & go run $checkerPath @Path
        if ($LASTEXITCODE -ne 0) {
            throw "go documentation check failed"
        }
    } finally {
        Pop-Location
    }
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
