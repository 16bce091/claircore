// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quay/claircore/internal/scanner (interfaces: Store)

// Package scanner is a generated GoMock package.
package scanner

import (
	gomock "github.com/golang/mock/gomock"
	claircore "github.com/quay/claircore"
	reflect "reflect"
)

// MockStore is a mock of Store interface
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// IndexPackages mocks base method
func (m *MockStore) IndexPackages(arg0 []*claircore.Package, arg1 *claircore.Layer, arg2 VersionedScanner) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IndexPackages", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// IndexPackages indicates an expected call of IndexPackages
func (mr *MockStoreMockRecorder) IndexPackages(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IndexPackages", reflect.TypeOf((*MockStore)(nil).IndexPackages), arg0, arg1, arg2)
}

// LayerScanned mocks base method
func (m *MockStore) LayerScanned(arg0 string, arg1 VersionedScanner) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LayerScanned", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LayerScanned indicates an expected call of LayerScanned
func (mr *MockStoreMockRecorder) LayerScanned(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LayerScanned", reflect.TypeOf((*MockStore)(nil).LayerScanned), arg0, arg1)
}

// ManifestScanned mocks base method
func (m *MockStore) ManifestScanned(arg0 string, arg1 VersionedScanners) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ManifestScanned", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ManifestScanned indicates an expected call of ManifestScanned
func (mr *MockStoreMockRecorder) ManifestScanned(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ManifestScanned", reflect.TypeOf((*MockStore)(nil).ManifestScanned), arg0, arg1)
}

// PackagesByLayer mocks base method
func (m *MockStore) PackagesByLayer(arg0 string, arg1 VersionedScanners) ([]*claircore.Package, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PackagesByLayer", arg0, arg1)
	ret0, _ := ret[0].([]*claircore.Package)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PackagesByLayer indicates an expected call of PackagesByLayer
func (mr *MockStoreMockRecorder) PackagesByLayer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PackagesByLayer", reflect.TypeOf((*MockStore)(nil).PackagesByLayer), arg0, arg1)
}

// RegisterScanners mocks base method
func (m *MockStore) RegisterScanners(arg0 VersionedScanners) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterScanners", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterScanners indicates an expected call of RegisterScanners
func (mr *MockStoreMockRecorder) RegisterScanners(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterScanners", reflect.TypeOf((*MockStore)(nil).RegisterScanners), arg0)
}

// ScanReport mocks base method
func (m *MockStore) ScanReport(arg0 string) (*claircore.ScanReport, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ScanReport", arg0)
	ret0, _ := ret[0].(*claircore.ScanReport)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ScanReport indicates an expected call of ScanReport
func (mr *MockStoreMockRecorder) ScanReport(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ScanReport", reflect.TypeOf((*MockStore)(nil).ScanReport), arg0)
}

// SetScanFinished mocks base method
func (m *MockStore) SetScanFinished(arg0 *claircore.ScanReport, arg1 VersionedScanners) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetScanFinished", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetScanFinished indicates an expected call of SetScanFinished
func (mr *MockStoreMockRecorder) SetScanFinished(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetScanFinished", reflect.TypeOf((*MockStore)(nil).SetScanFinished), arg0, arg1)
}

// SetScanReport mocks base method
func (m *MockStore) SetScanReport(arg0 *claircore.ScanReport) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetScanReport", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetScanReport indicates an expected call of SetScanReport
func (mr *MockStoreMockRecorder) SetScanReport(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetScanReport", reflect.TypeOf((*MockStore)(nil).SetScanReport), arg0)
}