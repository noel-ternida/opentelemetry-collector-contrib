// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ottl // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type PathExpressionParser[K any] func(*Path) (GetSetter[K], error)

type EnumParser func(*EnumSymbol) (*Enum, error)

type Enum int64

func (p *Parser[K]) newFunctionCall(inv invocation) (ExprFunc[K], error) {
	f, ok := p.functions[inv.Function]
	if !ok {
		return nil, fmt.Errorf("undefined function %v", inv.Function)
	}
	args, err := p.buildArgs(inv, reflect.TypeOf(f))
	if err != nil {
		return nil, err
	}

	returnVals := reflect.ValueOf(f).Call(args)

	if returnVals[1].IsNil() {
		err = nil
	} else {
		err = returnVals[1].Interface().(error)
	}

	return returnVals[0].Interface().(ExprFunc[K]), err
}

func (p *Parser[K]) buildArgs(inv invocation, fType reflect.Type) ([]reflect.Value, error) {
	var args []reflect.Value
	// Some function arguments may be intended to take values from the calling processor
	// instead of being passed by the caller of the OTTL function, so we have to keep
	// track of the index of the argument passed within the DSL.
	// e.g. TelemetrySettings, which is provided by the processor to the OTTL Parser struct.
	DSLArgumentIndex := 0
	for i := 0; i < fType.NumIn(); i++ {
		argType := fType.In(i)

		switch argType.Kind() {
		case reflect.Slice:
			err := p.buildSliceArg(inv, argType, i, &args)
			if err != nil {
				return nil, err
			}
			// Slice arguments must be the final argument in an invocation.
			return args, nil
		default:
			isInternalArg := p.buildInternalArg(argType, &args)

			if isInternalArg {
				continue
			}

			if DSLArgumentIndex >= len(inv.Arguments) {
				return nil, fmt.Errorf("not enough arguments for function %v", inv.Function)
			}

			argDef := inv.Arguments[DSLArgumentIndex]
			err := p.buildArg(argDef, argType, DSLArgumentIndex, &args)
			DSLArgumentIndex++
			if err != nil {
				return nil, err
			}
		}
	}

	if len(inv.Arguments) > DSLArgumentIndex {
		return nil, fmt.Errorf("too many arguments for function %v", inv.Function)
	}

	return args, nil
}

func (p *Parser[K]) buildSliceArg(inv invocation, argType reflect.Type, startingIndex int, args *[]reflect.Value) error {
	name := argType.Elem().Name()
	switch {
	case name == reflect.String.String():
		var arg []string
		for j := startingIndex; j < len(inv.Arguments); j++ {
			if inv.Arguments[j].String == nil {
				return fmt.Errorf("invalid argument for slice parameter at position %v, must be a string", j)
			}
			arg = append(arg, *inv.Arguments[j].String)
		}
		*args = append(*args, reflect.ValueOf(arg))
	case name == reflect.Float64.String():
		var arg []float64
		for j := startingIndex; j < len(inv.Arguments); j++ {
			if inv.Arguments[j].Float == nil {
				return fmt.Errorf("invalid argument for slice parameter at position %v, must be a float", j)
			}
			arg = append(arg, *inv.Arguments[j].Float)
		}
		*args = append(*args, reflect.ValueOf(arg))
	case name == reflect.Int64.String():
		var arg []int64
		for j := startingIndex; j < len(inv.Arguments); j++ {
			if inv.Arguments[j].Int == nil {
				return fmt.Errorf("invalid argument for slice parameter at position %v, must be an int", j)
			}
			arg = append(arg, *inv.Arguments[j].Int)
		}
		*args = append(*args, reflect.ValueOf(arg))
	case name == reflect.Uint8.String():
		if inv.Arguments[startingIndex].Bytes == nil {
			return fmt.Errorf("invalid argument for slice parameter at position %v, must be a byte slice literal", startingIndex)
		}
		*args = append(*args, reflect.ValueOf(([]byte)(*inv.Arguments[startingIndex].Bytes)))
	case strings.HasPrefix(name, "Getter"):
		var arg []Getter[K]
		for j := startingIndex; j < len(inv.Arguments); j++ {
			val, err := p.newGetter(inv.Arguments[j])
			if err != nil {
				return err
			}
			arg = append(arg, val)
		}
		*args = append(*args, reflect.ValueOf(arg))
	default:
		return fmt.Errorf("unsupported slice type '%s' for function '%v'", argType.Elem().Name(), inv.Function)
	}
	return nil
}

// Handle interfaces that can be passed as arguments to OTTL function invocations.
func (p *Parser[K]) buildArg(argDef value, argType reflect.Type, index int, args *[]reflect.Value) error {
	name := argType.Name()
	switch {
	case strings.HasPrefix(name, "Setter"):
		fallthrough
	case strings.HasPrefix(name, "GetSetter"):
		arg, err := p.pathParser(argDef.Path)
		if err != nil {
			return fmt.Errorf("invalid argument at position %v %w", index, err)
		}
		*args = append(*args, reflect.ValueOf(arg))
	case strings.HasPrefix(name, "Getter"):
		arg, err := p.newGetter(argDef)
		if err != nil {
			return fmt.Errorf("invalid argument at position %v %w", index, err)
		}
		*args = append(*args, reflect.ValueOf(arg))
	case name == "Enum":
		arg, err := p.enumParser(argDef.Enum)
		if err != nil {
			return fmt.Errorf("invalid argument at position %v must be an Enum", index)
		}
		*args = append(*args, reflect.ValueOf(*arg))
	case name == "string":
		if argDef.String == nil {
			return fmt.Errorf("invalid argument at position %v, must be an string", index)
		}
		*args = append(*args, reflect.ValueOf(*argDef.String))
	case name == "float64":
		if argDef.Float == nil {
			return fmt.Errorf("invalid argument at position %v, must be an float", index)
		}
		*args = append(*args, reflect.ValueOf(*argDef.Float))
	case name == "int64":
		if argDef.Int == nil {
			return fmt.Errorf("invalid argument at position %v, must be an int", index)
		}
		*args = append(*args, reflect.ValueOf(*argDef.Int))
	case name == "bool":
		if argDef.Bool == nil {
			return fmt.Errorf("invalid argument at position %v, must be a bool", index)
		}
		*args = append(*args, reflect.ValueOf(bool(*argDef.Bool)))
	default:
		return errors.New("unsupported argument type")
	}
	return nil
}

// Handle interfaces that can be declared as parameters to a OTTL function, but will
// never be called in an invocation. Returns whether the arg is an internal arg.
func (p *Parser[K]) buildInternalArg(argType reflect.Type, args *[]reflect.Value) bool {
	switch argType.Name() {
	case "TelemetrySettings":
		*args = append(*args, reflect.ValueOf(p.telemetrySettings))
	default:
		return false
	}

	return true
}
