// Copyright 2020 The Operator-SDK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helm

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	genutil "github.com/operator-framework/operator-sdk/internal/cmd/operator-sdk/generate/internal"
	"github.com/operator-framework/operator-sdk/internal/generate/collector"
	"github.com/operator-framework/operator-sdk/internal/util/projutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/chartutil"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/kubebuilder/v3/pkg/config"
	"sigs.k8s.io/yaml"
)

var longHelp = `
Running 'generate helm chart' will generate a helm chart based on the manifests for this project.

an operator PROJECT file is expected in the directory this command is run from (.)

options:
- ` + manifestDirectory + `: where the manifests for the operator project can be located; default: ` + defaultManifestDirectory + `
- ` + outputDirectory + `: where the output chart will end up or the existing chart to merge into; default: ` + defaultOutputDirectory + `
- ` + replaceExisting + `: whether to keep the existing values or the new ones when both exist; default: ` + fmt.Sprintf("%v", defaultReplaceExisting) + `
`

const examples = `
  $ operator-sdk generate helm chart

  based on default values:
  - an operator PROJECT file is at .
  - manifests have been generated into ./config/**
    - overridden with --` + manifestDirectory + `
  - chart output will be generated into ./chart
    - overridden with --` + outputDirectory + `

  folders containing yaml manifests for your operator:
  config
  ├── crd
  │   └── [...]
  ├─ default
  │   └── [...]
  └─ [...]
  (the output of 'make manifests' in your project's makefile)

  results in
  chart
  ├── charts
  │   └── []
  ├─ templates
  │   └── [...]
  ├─ .helmignore
  ├─ Chart.yaml
  └─ values.yaml

  if the charts folder was empty or didn't exist then a default helm template is populated and manifests and values from the operator are merged into the new chart
  
  if the charts folder was not empty then files are merged (matched by name) by value (matched by key).
  existing values are preserved unless --` + replaceExisting + `was specified, in which case new values replace old ones
`

//todo refactor for clarity and for unit tests
//-- probs not great to have this all be on big file with a bunch of long functions
//todo try to keep the order of the original when merging except when it has to be changed for grouping/control structures
//todo don't throw away comments
//todo don't throw away blank lines, they are meaningful in yaml

type chartCmd struct {
	replaceExistingValues bool
	manifestDirectory     string
	outputDirectory       string
	cfg                   config.Config
}

type template struct {
	name    string
	content string
}

type yamlRoot struct {
	nodes    map[string]*yamlNode
	controls []controlStructure
}

type yamlNode struct {
	key        string
	path       []string
	nodes      map[string]*yamlNode
	controls   []controlStructure
	value      *string
	isListItem bool
	keyOnly    bool
}

type controlCode struct {
	code        string
	indentation int
}

type controlStructure struct {
	start    controlCode
	end      *controlCode
	nodes    map[string]*yamlNode
	controls []controlStructure
}

func newChartCmd() *cobra.Command {
	chartCommand := &chartCmd{}
	cmd := &cobra.Command{
		Use:     "chart",
		Short:   "Generates Helm charts for operator-framework operator",
		Long:    longHelp,
		Example: examples,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := chartCommand.checkRequired(); err != nil {
				return err
			}

			cfg, err := projutil.ReadConfig()
			if err != nil {
				return fmt.Errorf("error reading configuration: %v", err)
			}

			if err = chartCommand.run(cfg); err != nil {
				log.Fatalf("Error generating chart files: %v", err)
			}

			return nil
		},
	}

	chartCommand.addFlagsTo(cmd.Flags())

	return cmd
}

const manifestDirectory = "manifestDirectory"
const outputDirectory = "outputDirectory"
const replaceExisting = "replaceExistingValues"
const defaultManifestDirectory = "./config"
const defaultOutputDirectory = "./chart"
const defaultReplaceExisting = false

func (chartCommand *chartCmd) addFlagsTo(fs *pflag.FlagSet) {
	fs.StringVar(&chartCommand.manifestDirectory, manifestDirectory, defaultManifestDirectory, "operator manifests to make chart from")
	fs.StringVar(&chartCommand.outputDirectory, outputDirectory, defaultOutputDirectory, "the location of the resulting chart")
	fs.BoolVar(&chartCommand.replaceExistingValues, replaceExisting, defaultReplaceExisting, "replace existing files with generated ones ones")
}

func (command *chartCmd) checkRequired() error {
	var errorMessages []string

	if command.manifestDirectory == "" {
		errorMessages = append(errorMessages, "--"+manifestDirectory+` is required
this should be the directory containing the manifests generated by your project
default:`+defaultOutputDirectory)
	}

	if command.outputDirectory == "" {
		errorMessages = append(errorMessages, "--"+outputDirectory+` is required
this is where the chart will end up; if it already contains a chart the two charts will be merged by value
default:`+defaultOutputDirectory+`
see `+replaceExisting)
	}

	if len(errorMessages) > 0 {
		return errors.New(strings.Join(errorMessages, "\n\n"))
	}

	return nil
}

func (chart *chartCmd) run(cfg config.Config) error {
	chart.cfg = cfg

	chartPath, err := chart.create()
	if err != nil {
		return err
	}

	err = chart.mergeExpectedValues()
	if err != nil {
		return err
	}

	chartObjects, err := chart.operatorResources()
	if err != nil {
		return err
	}

	templates, err := chart.tranlsateToHelmTemplates(chartObjects)
	if err != nil {
		return err
	}

	return chart.mergeTemplatesIntoChart(chartPath, templates)
}

func (chart *chartCmd) create() (string, error) {
	exists, err := fileExists(chart.outputDirectory)
	if err != nil {
		return "", err
	}

	if !exists {
		chartDirectory, err := chartutil.Create(chart.cfg.GetProjectName(), filepath.Dir(chart.outputDirectory))
		if err != nil {
			return "", err
		}

		if err = os.Rename(chartDirectory, chart.outputDirectory); err != nil {
			return "", err
		}

		return chart.outputDirectory, nil
	}

	tempDirectory, err := chartutil.Create(chart.cfg.GetProjectName(), os.TempDir())
	defer os.RemoveAll(tempDirectory)
	if err != nil {
		return "", err
	}

	filepath.WalkDir(tempDirectory, func(path string, file os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if file.IsDir() {
			return nil
		}

		rawTemplate, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		template := template{
			name:    strings.Split(filepath.Base(path), ".")[0],
			content: string(rawTemplate),
		}
		finalTemplate, err := chart.mergeTemplateIntoFile(chart.outputDirectory, template)
		if err != nil {
			return err
		}

		return os.WriteFile(finalTemplate.name, []byte(finalTemplate.content), 0755)
	})

	return chart.outputDirectory, nil
}

func (chart *chartCmd) mergeExpectedValues() error {
	values := `
monitoring:
  enabled: false
`

	valuesPath := filepath.Join(chart.outputDirectory, "values.yaml")
	mergedValues, err := chart.mergeYamlIntoFile(valuesPath, values)
	if err != nil {
		return err
	}

	return os.WriteFile(valuesPath, []byte(mergedValues), 0755)
}

func fileExists(elem ...string) (bool, error) {
	if _, err := os.Stat(filepath.Join(elem...)); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

func (chart *chartCmd) operatorResources() ([]client.Object, error) {
	collector := &collector.Manifests{}

	err := collector.UpdateFromDir(chart.manifestDirectory)
	if err != nil {
		return nil, err
	}

	return genutil.GetManifestObjects(collector, nil), nil
}

func (chart *chartCmd) tranlsateToHelmTemplates(objects []client.Object) (templates []template, err error) {
	for _, object := range objects {
		if object.GetObjectKind().GroupVersionKind().Kind == "Namespace" {
			continue
		}
		object.SetNamespace("")

		marshalled, err := yaml.Marshal(object)
		if err != nil {
			return nil, err
		}

		templateYaml := parseYaml(string(marshalled), nil)
		nodes := templateYaml.flatMap()

		//try not to use any scope-altering [range, with, ...] or scope dependent functionality [.Values vs $.Values]
		//altering scope or scope dependent functionality would require fully parsing out both templates on merging
		//in order to maintain both then fully reversing them, which might not actually always be possible
		name := nodes["metadata.name"]
		if name != nil {
			value := fmt.Sprintf("{{ include \"%s.fullname\" $ }}-%s", chart.cfg.GetProjectName(), *name.value)
			name.value = &value
		}

		labels := nodes["metadata.labels"]
		if labels != nil {
			value := fmt.Sprintf("\n    {{- include \"%s.labels\" $ | nindent 4 }}", chart.cfg.GetProjectName())
			labels.value = &value
		}

		if object.GetObjectKind().GroupVersionKind().Kind == "ServiceMonitor" {
			if templateYaml.controls == nil {
				templateYaml.controls = []controlStructure{}
			}

			control := controlStructure{
				start: controlCode{
					code:        "{{- if $.Values.monitoring.enabled }}",
					indentation: 0,
				},
				nodes:    templateYaml.nodes,
				controls: templateYaml.controls,
				end: &controlCode{
					code:        "{{- end }}",
					indentation: 0,
				},
			}
			templateYaml.nodes = nil
			templateYaml.controls = []controlStructure{control}
		}

		template := template{
			name:    genutil.MakeObjectFileName(object),
			content: writeYamlTree(templateYaml),
		}
		templates = append(templates, template)
	}

	return templates, nil
}

func (root yamlRoot) flatMap() map[string]*yamlNode {
	nodes := map[string]*yamlNode{}
	var flatMapNode func(node *yamlNode)
	var flatMapControl func(control *controlStructure)

	flatMapNode = func(node *yamlNode) {
		nodes[strings.Join(append(node.path, node.key), ".")] = node

		if node.nodes != nil {
			for _, node := range node.nodes {
				flatMapNode(node)
			}
		}
		if node.controls != nil {
			for _, control := range node.controls {
				flatMapControl(&control)
			}
		}
	}
	flatMapControl = func(control *controlStructure) {
		if control.nodes != nil {
			for _, node := range control.nodes {
				flatMapNode(node)
			}
		}
		if control.controls != nil {
			for _, control := range control.controls {
				flatMapControl(&control)
			}
		}
	}
	if root.nodes != nil {
		for _, node := range root.nodes {
			flatMapNode(node)
		}
	}
	if root.controls != nil {
		for _, control := range root.controls {
			flatMapControl(&control)
		}
	}

	return nodes
}

func (chart *chartCmd) mergeTemplatesIntoChart(path string, templates []template) error {
	for _, template := range templates {
		renderedTemplate, err := chart.mergeTemplateIntoFile(path, template)
		if err != nil {
			return err
		}

		err = os.WriteFile(filepath.Join(path, "templates", renderedTemplate.name), []byte(renderedTemplate.content), 0755)
		if err != nil {
			return err
		}
	}

	return nil
}

func (chart *chartCmd) mergeTemplateIntoFile(path string, incomingTemplate template) (*template, error) {
	templates := filepath.Join(path, "templates")

	exists, err := fileExists(templates, incomingTemplate.name)
	if err != nil {
		return nil, err
	}

	if !exists {
		return &incomingTemplate, nil
	}

	mergedContent, err := chart.mergeYamlIntoFile(filepath.Join(templates, incomingTemplate.name), incomingTemplate.content)
	if err != nil {
		return nil, err
	}

	return &template{
		name:    incomingTemplate.name,
		content: mergedContent,
	}, nil
}

//this becomes more complicated if the templates being merged in start to contain
//-- scope-dependent values (.[...] instead of $.[...])
//-- scope modifying template functions (with, range)
//... so just don't
func (chart *chartCmd) mergeYamlIntoFile(path string, content string) (string, error) {
	existingContent, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	existingTemplateRoot := parseYaml(string(existingContent), nil)
	newTemplateRoot := parseYaml(content, nil)

	templateRoot := chart.mergeYamlTrees(existingTemplateRoot, newTemplateRoot)
	if templateRoot.controls == nil && templateRoot.nodes == nil {
		return "", errors.New("parse error merging template files")
	}

	return writeYamlTree(templateRoot), nil
}

//if this seems like a lot of work considering there is already a package for marshalling yaml (even in use here)
//helm templates are not NECESSARILY valid yaml.  They can be but likely aren't.
func parseYaml(yaml string, path []string) (root yamlRoot) {
	var parseNode func(current string) (node *yamlNode, remaining string)
	var parseControlStructure func(current string) (control *controlStructure, remaining string)

	parseNode = func(current string) (node *yamlNode, remaining string) {
		parts := strings.SplitN(current, "\n", 2)
		line := strings.Trim(strings.SplitN(parts[0], "#", 2)[0], " \r\n")
		depth := (len(strings.TrimRight(parts[0], " ")) - len(line)) / 2
		if len(parts) == 2 {
			remaining = parts[1]
		} else {
			remaining = ""
		}

		//todo don't throw away comments, that's rude
		//they don't have any (yaml) location information when they're on their own line
		if len(line) == 0 {
			return nil, remaining
		}

		node = &yamlNode{
			key:  strings.SplitN(line, ":", 2)[0],
			path: path,
		}

		remainingLines := remaining
		peekNextLine := func() string {
			return strings.SplitN(remainingLines, "\n", 2)[0]
		}
		nextLine := func() string {
			lines := strings.SplitN(remainingLines, "\n", 2)
			if len(lines) > 1 {
				remainingLines = lines[1]
			} else {
				remainingLines = ""
			}

			return lines[0]
		}

		isMultiLineString := func() (bool, string, *regexp.Regexp) {
			if strings.HasSuffix(line, "|") {
				unquotedEnd := regexp.MustCompile(fmt.Sprintf(`(?m)^(  ){0,%d}.*:`, depth))
				return true, `|`, unquotedEnd
			}

			if regexp.MustCompile(`(?m)^.*:\s+'`).MatchString(line) {
				singleQuoteEnd := regexp.MustCompile(`(?m)[^']'\s*$`)
				return !singleQuoteEnd.MatchString(line), `'`, singleQuoteEnd
			}

			if regexp.MustCompile(`(?m)^.*:\s+"`).MatchString(line) {
				doubleQuoteEnd := regexp.MustCompile(`(?m)"\s*$`)
				return !doubleQuoteEnd.MatchString(line), `"`, doubleQuoteEnd
			}

			nextLine := peekNextLine()
			if regexp.MustCompile(`(?m)^.*:\s+`).MatchString(line) && strings.HasPrefix(nextLine, strings.Repeat("  ", depth+1)) {
				unquotedEnd := regexp.MustCompile(fmt.Sprintf(`(?m)^(  ){0,%d}.*:`, depth))
				return !unquotedEnd.MatchString(nextLine), "", unquotedEnd
			}

			//todo: if the next line is a control or template function need to determine if it should be aprt of this node's multiline value
			//  or if it's around the next set of nodes...
			//-- if it's a template function that produces more nodes it can be text
			//-- if it's a range it might be around more multiline text or it might be around the next set of nodes
			if regexp.MustCompile(`(?m)^.*:+`).MatchString(line) && strings.HasPrefix(strings.TrimLeft(nextLine, " "), "{{") {
				if 
				unquotedEnd := regexp.MustCompile(fmt.Sprintf(`(?m)^(  ){0,%d}.*:`, depth))
				return !unquotedEnd.MatchString(nextLine), "", unquotedEnd
			}

			return false, "", nil
		}

		if isMultiLine, opening, closing := isMultiLineString(); isMultiLine {
			if opening == `|` {
				value := "|\n"
				node.value = &value
			} else {
				value := strings.SplitN(line, ": ", 2)[1] + "\n"
				node.value = &value
			}

			terminatingLineEnd := len(remaining)
			if terminatingLine := closing.FindStringIndex(remaining); terminatingLine != nil {
				terminatingLineEnd = terminatingLine[1]
			}

			*node.value += remaining[:terminatingLineEnd]
			remaining = remaining[terminatingLineEnd:]
		} else if strings.HasPrefix(line, "- ") {
			node.isListItem = true
			node.key = strings.TrimPrefix(node.key, "- ")

			if strings.Contains(line, ":") {
				if strings.Contains(line, ": ") {
					node.value = &strings.SplitN(line, ": ", 2)[1]
				}

				nextList := regexp.MustCompile(fmt.Sprintf(`(?m)^(  ){%d}- \S`, depth)).FindStringIndex(remaining)
				lineAfterListEnd := regexp.MustCompile(fmt.Sprintf(`(?m)^(  ){0,%d}\S`, depth)).FindStringIndex(remaining)
				subYaml := ""

				if nextList != nil {
					if lineAfterListEnd != nil {
						if nextList[0] < lineAfterListEnd[0] {
							subYaml = remaining[:nextList[0]]
						} else {
							subYaml = remaining[:lineAfterListEnd[0]]
						}
					} else {
						subYaml = remaining[:lineAfterListEnd[0]]
					}
				} else if lineAfterListEnd != nil {
					subYaml = remaining[:lineAfterListEnd[0]]
				} else {
					subYaml = remaining
				}
				remaining = remaining[len(subYaml):]

				subroot := parseYaml(subYaml, append(path, node.key))
				node.nodes = subroot.nodes
				node.controls = subroot.controls
			} else {
				node.keyOnly = true
			}
		} else if strings.HasSuffix(line, ":") {
			subYaml := ""

			isIncluded := func(line string) bool {
				lineContent := strings.TrimPrefix(line, strings.Repeat("  ", depth))

				if strings.HasPrefix(lineContent, "  ") {
					return true
				}

				if strings.HasPrefix(lineContent, "- ") {
					return true
				}

				if strings.HasPrefix(strings.TrimLeft(lineContent, " "), "{{") {
					return true
				}

				return false
			}
			next := nextLine()
			for isIncluded(next) {
				subYaml += next + "\n"
				next = nextLine()
			}
			subYaml = strings.TrimSuffix(subYaml, "\n")
			remaining = remaining[len(subYaml):]

			subroot := parseYaml(subYaml, append(path, node.key))
			node.nodes = subroot.nodes
			node.controls = subroot.controls
		} else {
			node.value = &strings.SplitN(line, ": ", 2)[1]
		}

		return node, remaining
	}
	parseControlStructure = func(current string) (control *controlStructure, remaining string) {
		parts := strings.SplitN(current, "\n", 2)
		line := parts[0]
		remaining = parts[1]
		control.start = controlCode{
			code:        line[strings.Index(line, "{{"):strings.LastIndex(line, "}}")],
			indentation: strings.Count(line[:strings.Index(line, "{{")], "  "),
		}

		rangeRegex := regexp.MustCompile(`(?m)^\s*{{-?\s*(if|with|range)\s+.*-?}}\s*$`)
		endRegex := regexp.MustCompile(`(?m)^\s*{{-?\s*end\s*-?}}\s*$`)

		if !rangeRegex.MatchString(line) {
			return control, remaining
		}

		nextRange := rangeRegex.FindStringIndex(remaining)
		nextEnd := endRegex.FindStringIndex(remaining)
		for nextRange != nil && nextRange[0] < nextEnd[0] {
			nextRange = rangeRegex.FindStringIndex(remaining)
			nextEnd = endRegex.FindStringIndex(remaining)
		}

		endLine := remaining[nextEnd[0]:nextEnd[1]]
		control.end = &controlCode{
			code:        strings.Trim(endLine, " "),
			indentation: strings.Count(line[:strings.Index(line, "{{")], "  "),
		}

		subYaml := remaining[:nextEnd[0]]
		subroot := parseYaml(subYaml, path)
		control.nodes = subroot.nodes
		control.controls = subroot.controls

		return control, remaining[:nextEnd[1]]
	}

	beforeParse := ""
	remaining := yaml
	for len(remaining) > 0 {
		//todo is line a control structure function based on regex
		//used here and above in parse node to determine if the following line belongs inside a node
		if strings.HasPrefix(strings.TrimLeft(remaining, " "), "{{") {
			control, r := parseControlStructure(remaining)
			root.controls = append(root.controls, *control)
			remaining = r
		} else {
			node, r := parseNode(remaining)
			if node != nil {
				if root.nodes == nil {
					root.nodes = map[string]*yamlNode{}
				}

				if node.isListItem {
					keyIndex := 0
					for _, existingNode := range root.nodes {
						if existingNode.key == node.key {
							keyIndex++
						}
					}

					index := fmt.Sprintf("[%d]", keyIndex)
					node.path[len(node.path)-1] = node.path[len(node.path)-1] + index
					root.nodes[node.key+index] = node
				} else {
					root.nodes[node.key] = node
				}
			}
			beforeParse = remaining
			remaining = r
		}
	}

	if beforeParse == "" {

	}

	return root
}

func (chart *chartCmd) mergeYamlTrees(existingTemplateRoot, newTemplateRoot yamlRoot) yamlRoot {
	var mergeNodes func(existingNode, newNode *yamlNode) (resultNode *yamlNode)
	var mergeControlStructures func(existingControl, newControl *controlStructure) (resultControl *controlStructure)
	var mergeControlledNodes func(control *controlStructure, nodes map[string]*yamlNode) (resultControl *controlStructure)

	mapControls := func(controls []controlStructure) (controlMap map[string]*controlStructure) {
		controlMap = map[string]*controlStructure{}

		for _, control := range controls {
			controlMap[control.start.code] = &control
		}

		return controlMap
	}

	mergeNodes = func(existingNode, newNode *yamlNode) (resultNode *yamlNode) {
		var baseNode *yamlNode
		var nodeToMerge *yamlNode
		if chart.replaceExistingValues {
			baseNode = newNode
			nodeToMerge = existingNode
		} else {
			baseNode = existingNode
			nodeToMerge = newNode
		}

		if nodeToMerge.value != nil {
			baseNode.value = nodeToMerge.value
		}

		//todo merge controls

		for _, node := range nodeToMerge.nodes {
			if baseNode.nodes[node.key] != nil {
				baseNode.nodes[node.key] = mergeNodes(existingNode.nodes[node.key], newNode.nodes[node.key])
			} else {
				baseNode.nodes[node.key] = node
			}
		}

		return baseNode
	}
	mergeControlStructures = func(existingControl, newControl *controlStructure) (resultControl *controlStructure) {
		if newControl.nodes != nil {
			for _, node := range newControl.nodes {
				if existingControl.nodes[node.key] != nil {
					existingControl.nodes[node.key] = mergeNodes(existingControl.nodes[node.key], node)
				} else {
					existingControl.nodes[node.key] = node
					uncontrolledParent := existingTemplateRoot.nodes
					for _, key := range node.path {
						if uncontrolledParent[key] != nil {
							uncontrolledParent = uncontrolledParent[key].nodes
						}
					}
					if uncontrolledParent != nil {
						delete(uncontrolledParent, node.key)
					}
				}
			}
		}

		if existingControl.controls != nil {
			existingControls := mapControls(existingControl.controls)
			for _, control := range newControl.controls {
				if existingControls[control.start.code] != nil {
					existingControl.controls = append(existingControl.controls, *mergeControlStructures(existingControls[control.start.code], &control))
				} else {
					existingControl.controls = append(existingControl.controls, control)
				}
			}
		}

		if chart.replaceExistingValues {
			existingControl.end = newControl.end
		}

		return existingControl
	}
	mergeControlledNodes = func(control *controlStructure, nodes map[string]*yamlNode) *controlStructure {
		for _, node := range nodes {
			if control.nodes[node.key] != nil {
				control.nodes[node.key] = mergeNodes(node, control.nodes[node.key])
			} else {
				control.nodes[node.key] = node
			}
		}

		return control
	}

	if newTemplateRoot.controls != nil {
		if existingTemplateRoot.controls != nil {
			existingControls := mapControls(existingTemplateRoot.controls)
			newControls := mapControls(newTemplateRoot.controls)
			for start, newControl := range newControls {
				if existingControls[start] != nil {
					mergedControl := mergeControlStructures(existingControls[start], newControl)
					existingTemplateRoot.controls = append(existingTemplateRoot.controls, *mergedControl)
				} else {
					uncontrolledOriginalNodes := map[string]*yamlNode{}
					if existingTemplateRoot.nodes != nil {
						for key, node := range existingTemplateRoot.nodes {
							if newControl.nodes[key] != nil {
								uncontrolledOriginalNodes[key] = node
							}
						}
					}

					newControl = mergeControlledNodes(newControl, uncontrolledOriginalNodes)
					for key := range uncontrolledOriginalNodes {
						delete(existingTemplateRoot.nodes, key)
					}

					existingTemplateRoot.controls = append(existingTemplateRoot.controls, *newControl)
				}
			}
		} else {
			existingTemplateRoot.controls = newTemplateRoot.controls
		}
	}

	if existingTemplateRoot.nodes != nil && newTemplateRoot.nodes != nil {
		for _, node := range newTemplateRoot.nodes {
			if existingTemplateRoot.nodes[node.key] != nil {
				existingTemplateRoot.nodes[node.key] = mergeNodes(existingTemplateRoot.nodes[node.key], node)
			} else {
				existingTemplateRoot.nodes[node.key] = node
			}
		}
	}

	return existingTemplateRoot
}

func writeYamlTree(root yamlRoot) (templateYaml string) {
	var writeNode func(node *yamlNode, depth int) string
	var writeControl func(control controlStructure, depth int) string
	indent := func(depth int) string {
		return strings.Repeat("  ", depth)
	}
	writeNode = func(node *yamlNode, depth int) string {
		result := indent(depth)

		key := node.key
		if node.isListItem {
			result = strings.TrimSuffix(result, "  ")
			key = "- " + key
		}
		result += key

		if !node.keyOnly {
			result += ":"
		}

		if node.value != nil {
			result += " " + *node.value + "\n"
		} else {
			result += "\n"
		}

		if node.controls != nil {
			for _, nestedControl := range node.controls {
				result += writeControl(nestedControl, depth)
			}
		}

		if node.nodes != nil {
			nonKeyOnlyResult := ""

			for _, child := range node.nodes {
				childDepth := depth + 1
				if node.isListItem && !child.isListItem {
					childDepth--
				}

				if child.keyOnly {
					result += writeNode(child, childDepth)
				} else {
					nonKeyOnlyResult += writeNode(child, childDepth)
				}
			}

			result += nonKeyOnlyResult
		}

		return result
	}
	writeControl = func(control controlStructure, depth int) string {
		result := indent(control.start.indentation) + control.start.code + "\n"

		if control.end == nil {
			return result
		}

		if control.controls != nil {
			for _, nestedControl := range control.controls {
				result += writeControl(nestedControl, depth)
			}
		}

		if control.nodes != nil {
			for _, node := range control.nodes {
				result += writeNode(node, depth)
			}
		}

		result += indent(control.end.indentation) + control.end.code + "\n"
		return result
	}

	//controlled blocks will always end up above uncontrolled
	//not actually a problem, but might be annoying for someone wanting to keep their file in a certain order
	//type unions would sure have made keeping the order extremely easy and simplified some stuff...
	//probably would have made some other parts more complicated with type check switching needed😉
	if root.controls != nil {
		for _, control := range root.controls {
			templateYaml += writeControl(control, 0)
		}
	}
	if root.nodes != nil {
		for _, node := range root.nodes {
			templateYaml += writeNode(node, 0)
		}
	}

	return templateYaml
}
