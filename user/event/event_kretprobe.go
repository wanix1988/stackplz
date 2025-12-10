package event

import (
	"encoding/json"
	"fmt"
	"stackplz/user/common"
	"stackplz/user/config"
	"stackplz/user/util"
	"strings"
)

type KretprobeEvent struct {
	ContextEvent
	UUID         string
	kretprobe_name string
	config.KretprobeFields
	Stack_str string
}

func (this *KretprobeEvent) DumpRecord() bool {
	return this.mconf.DumpRecord(common.KPROBE_EVENT, &this.rec)
}

func (this *KretprobeEvent) ParseEvent() (IEventStruct, error) {
	data_e, err := this.ContextEvent.ParseEvent()
	if err != nil {
		panic("...")
	}
	if data_e == nil {
		if err := this.ParseContext(); err != nil {
			panic(fmt.Sprintf("KretprobeEvent.ParseContext() err:%v", err))
		}
		return this, nil
	}
	return data_e, nil
}

func (this *KretprobeEvent) ParseContext() (err error) {
	if this.EventId != KPROBE_EXIT {
		panic(fmt.Sprintf("KretprobeEvent.ParseContext() failed, EventId:%d", this.EventId))
	}

	// 读取函数名长度和函数名
	var func_name_len uint32
	this.ReadArg(&func_name_len)
	func_name_bytes := make([]byte, func_name_len)
	if err = this.ReadValue(func_name_bytes); err != nil {
		panic(err)
	}
	this.FuncName = util.B2STrim(func_name_bytes)
	this.kretprobe_name = this.FuncName

	// 读取返回值
	this.ReadArg(&this.RetValue)

	// 解析返回值相关的参数（如果有配置）
	var results []string
	results = append(results, fmt.Sprintf("ret=0x%x", this.RetValue))
	this.ArgStr = "(" + strings.Join(results, ", ") + ")"
	this.ArgName = this.FuncName

	this.ParsePadding()
	err = this.ParseContextStack()
	if err != nil {
		panic(fmt.Sprintf("ParseContextStack err:%v", err))
	}
	return nil
}

func (this *KretprobeEvent) Clone() IEventStruct {
	event := new(KretprobeEvent)
	return event
}

func (this *KretprobeEvent) GetUUID() string {
	s := fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
	if this.mconf.ShowTime {
		s = fmt.Sprintf("%d|%s", this.Ts, s)
	}
	if this.mconf.ShowUid {
		s = fmt.Sprintf("%d|%s", this.Uid, s)
	}
	return s
}

func (this *KretprobeEvent) MarshalJSON() ([]byte, error) {
	type ContextAlias config.ContextFields
	type KretprobeAlias config.KretprobeFields
	return json.Marshal(&struct {
		Event string `json:"event"`
		Comm  string `json:"comm"`
		*ContextAlias
		*KretprobeAlias
		Stack_str string `json:"stack_str"`
	}{
		Event:        "kretprobe",
		Comm:         util.B2STrim(this.Comm[:]),
		ContextAlias: (*ContextAlias)(&this.ContextFields),
		KretprobeAlias: (*KretprobeAlias)(&this.KretprobeFields),
		Stack_str:    this.Stack_str,
	})
}

func (this *KretprobeEvent) String() string {
	this.Stack_str = this.GetStackTrace("")

	if this.mconf.FmtJson {
		data, err := json.Marshal(this)
		if err != nil {
			panic(err)
		}
		return string(data)
	}

	var s string
	s = fmt.Sprintf("[%s] %s%s ret=0x%x", this.GetUUID(), this.FuncName, this.ArgStr, this.RetValue)

	return s + this.Stack_str
}

