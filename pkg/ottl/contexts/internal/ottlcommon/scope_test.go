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

package ottlcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottltest"
)

func TestScopePathGetSetter(t *testing.T) {
	refIS := createInstrumentationScope()

	newAttrs := pcommon.NewMap()
	newAttrs.PutString("hello", "world")
	tests := []struct {
		name     string
		path     []ottl.Field
		orig     interface{}
		newVal   interface{}
		modified func(is pcommon.InstrumentationScope)
	}{
		{
			name:   "instrumentation_scope",
			path:   []ottl.Field{},
			orig:   refIS,
			newVal: pcommon.NewInstrumentationScope(),
			modified: func(is pcommon.InstrumentationScope) {
				pcommon.NewInstrumentationScope().CopyTo(is)
			},
		},
		{
			name: "instrumentation_scope name",
			path: []ottl.Field{
				{
					Name: "name",
				},
			},
			orig:   refIS.Name(),
			newVal: "newname",
			modified: func(is pcommon.InstrumentationScope) {
				is.SetName("newname")
			},
		},
		{
			name: "instrumentation_scope version",
			path: []ottl.Field{
				{
					Name: "version",
				},
			},
			orig:   refIS.Version(),
			newVal: "next",
			modified: func(is pcommon.InstrumentationScope) {
				is.SetVersion("next")
			},
		},
		{
			name: "attributes",
			path: []ottl.Field{
				{
					Name: "attributes",
				},
			},
			orig:   refIS.Attributes(),
			newVal: newAttrs,
			modified: func(is pcommon.InstrumentationScope) {
				newAttrs.CopyTo(is.Attributes())
			},
		},
		{
			name: "attributes string",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("str"),
				},
			},
			orig:   "val",
			newVal: "newVal",
			modified: func(is pcommon.InstrumentationScope) {
				is.Attributes().PutString("str", "newVal")
			},
		},
		{
			name: "attributes bool",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("bool"),
				},
			},
			orig:   true,
			newVal: false,
			modified: func(is pcommon.InstrumentationScope) {
				is.Attributes().PutBool("bool", false)
			},
		},
		{
			name: "attributes int",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("int"),
				},
			},
			orig:   int64(10),
			newVal: int64(20),
			modified: func(is pcommon.InstrumentationScope) {
				is.Attributes().PutInt("int", 20)
			},
		},
		{
			name: "attributes float",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("double"),
				},
			},
			orig:   1.2,
			newVal: 2.4,
			modified: func(is pcommon.InstrumentationScope) {
				is.Attributes().PutDouble("double", 2.4)
			},
		},
		{
			name: "attributes bytes",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("bytes"),
				},
			},
			orig:   []byte{1, 3, 2},
			newVal: []byte{2, 3, 4},
			modified: func(is pcommon.InstrumentationScope) {
				is.Attributes().PutEmptyBytes("bytes").FromRaw([]byte{2, 3, 4})
			},
		},
		{
			name: "attributes array string",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("arr_str"),
				},
			},
			orig: func() pcommon.Slice {
				val, _ := refIS.Attributes().Get("arr_str")
				return val.Slice()
			}(),
			newVal: []string{"new"},
			modified: func(is pcommon.InstrumentationScope) {
				newArr := is.Attributes().PutEmptySlice("arr_str")
				newArr.AppendEmpty().SetStr("new")
			},
		},
		{
			name: "attributes array bool",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("arr_bool"),
				},
			},
			orig: func() pcommon.Slice {
				val, _ := refIS.Attributes().Get("arr_bool")
				return val.Slice()
			}(),
			newVal: []bool{false},
			modified: func(is pcommon.InstrumentationScope) {
				newArr := is.Attributes().PutEmptySlice("arr_bool")
				newArr.AppendEmpty().SetBool(false)
			},
		},
		{
			name: "attributes array int",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("arr_int"),
				},
			},
			orig: func() pcommon.Slice {
				val, _ := refIS.Attributes().Get("arr_int")
				return val.Slice()
			}(),
			newVal: []int64{20},
			modified: func(is pcommon.InstrumentationScope) {
				newArr := is.Attributes().PutEmptySlice("arr_int")
				newArr.AppendEmpty().SetInt(20)
			},
		},
		{
			name: "attributes array float",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("arr_float"),
				},
			},
			orig: func() pcommon.Slice {
				val, _ := refIS.Attributes().Get("arr_float")
				return val.Slice()
			}(),
			newVal: []float64{2.0},
			modified: func(is pcommon.InstrumentationScope) {
				newArr := is.Attributes().PutEmptySlice("arr_float")
				newArr.AppendEmpty().SetDouble(2.0)
			},
		},
		{
			name: "attributes array bytes",
			path: []ottl.Field{
				{
					Name:   "attributes",
					MapKey: ottltest.Strp("arr_bytes"),
				},
			},
			orig: func() pcommon.Slice {
				val, _ := refIS.Attributes().Get("arr_bytes")
				return val.Slice()
			}(),
			newVal: [][]byte{{9, 6, 4}},
			modified: func(is pcommon.InstrumentationScope) {
				newArr := is.Attributes().PutEmptySlice("arr_bytes")
				newArr.AppendEmpty().SetEmptyBytes().FromRaw([]byte{9, 6, 4})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor, err := ScopePathGetSetter[*instrumentationScopeContext](tt.path)
			assert.NoError(t, err)

			is := createInstrumentationScope()

			got := accessor.Get(newInstrumentationScopeContext(is))
			assert.Equal(t, tt.orig, got)

			accessor.Set(newInstrumentationScopeContext(is), tt.newVal)

			expectedIS := createInstrumentationScope()
			tt.modified(expectedIS)

			assert.Equal(t, expectedIS, is)
		})
	}
}

func createInstrumentationScope() pcommon.InstrumentationScope {
	is := pcommon.NewInstrumentationScope()
	is.SetName("library")
	is.SetVersion("version")

	is.Attributes().PutString("str", "val")
	is.Attributes().PutBool("bool", true)
	is.Attributes().PutInt("int", 10)
	is.Attributes().PutDouble("double", 1.2)
	is.Attributes().PutEmptyBytes("bytes").FromRaw([]byte{1, 3, 2})

	arrStr := is.Attributes().PutEmptySlice("arr_str")
	arrStr.AppendEmpty().SetStr("one")
	arrStr.AppendEmpty().SetStr("two")

	arrBool := is.Attributes().PutEmptySlice("arr_bool")
	arrBool.AppendEmpty().SetBool(true)
	arrBool.AppendEmpty().SetBool(false)

	arrInt := is.Attributes().PutEmptySlice("arr_int")
	arrInt.AppendEmpty().SetInt(2)
	arrInt.AppendEmpty().SetInt(3)

	arrFloat := is.Attributes().PutEmptySlice("arr_float")
	arrFloat.AppendEmpty().SetDouble(1.0)
	arrFloat.AppendEmpty().SetDouble(2.0)

	arrBytes := is.Attributes().PutEmptySlice("arr_bytes")
	arrBytes.AppendEmpty().SetEmptyBytes().FromRaw([]byte{1, 2, 3})
	arrBytes.AppendEmpty().SetEmptyBytes().FromRaw([]byte{2, 3, 4})

	return is
}

type instrumentationScopeContext struct {
	is pcommon.InstrumentationScope
}

func (r *instrumentationScopeContext) GetInstrumentationScope() pcommon.InstrumentationScope {
	return r.is
}

func newInstrumentationScopeContext(is pcommon.InstrumentationScope) *instrumentationScopeContext {
	return &instrumentationScopeContext{is: is}
}
