package event

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"stackplz/user/argtype"
	"stackplz/user/common"
	"stackplz/user/config"
	"stackplz/user/util"
	"strings"
	"syscall"
)

type UretprobeEvent struct {
	ContextEvent
	UUID         string
	uprobe_point *config.UprobeArgs
	config.UretprobeFields
	Stack_str string
}

func (this *UretprobeEvent) DumpRecord() bool {
	return this.mconf.DumpRecord(common.UPROBE_EVENT, &this.rec)
}

func (this *UretprobeEvent) ParseEvent() (IEventStruct, error) {
	data_e, err := this.ContextEvent.ParseEvent()
	if err != nil {
		panic("...")
	}
	if data_e == nil {
		if err := this.ParseContext(); err != nil {
			panic(fmt.Sprintf("UretprobeEvent.ParseContext() err:%v", err))
		}
		return this, nil
	}
	return data_e, nil
}

func (this *UretprobeEvent) ParseContext() (err error) {
	if this.EventId != UPROBE_EXIT {
		panic(fmt.Sprintf("UretprobeEvent.ParseContext() failed, EventId:%d", this.EventId))
	}

	// 读取 probe_index
	this.ReadArg(&this.ProbeIndex)
	// 读取返回值
	this.ReadArg(&this.RetValue)
	// 读取 LR, SP, PC
	this.ReadArg(&this.LR)
	this.ReadArg(&this.SP)
	this.ReadArg(&this.PC)

	// 根据预设索引解析参数
	if (this.ProbeIndex + 1) > uint32(len(this.mconf.StackUprobeConf.Points)) {
		panic(fmt.Sprintf("probe_index %d bigger than points", this.ProbeIndex))
	}
	this.uprobe_point = this.mconf.StackUprobeConf.Points[this.ProbeIndex]
	this.ArgName = this.uprobe_point.Name
	if this.uprobe_point.KillSignal == uint32(syscall.SIGSTOP) && this.Pid != 0 {
		AddStopped(this.Pid)
	}

	// 解析返回值相关的参数（如果有配置）
	var results []string
	// 首先添加返回值
	results = append(results, fmt.Sprintf("ret=0x%x", this.RetValue))

	// 如果有配置的返回参数读取，则解析
	for _, point_arg := range this.uprobe_point.PointArgs {
		var ptr argtype.Arg_reg
		if err := binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
			panic(err)
		}
		arg_fmt := point_arg.Parse(ptr.Address, this.buf, config.EBPF_UPROBE_EXIT)
		results = append(results, fmt.Sprintf("%s=%s", point_arg.Name, arg_fmt))
	}
	this.ArgStr = "(" + strings.Join(results, ", ") + ")"
	this.ParsePadding()
	err = this.ParseContextStack()
	if err != nil {
		panic(fmt.Sprintf("ParseContextStack err:%v", err))
	}
	if this.mconf.AutoResume {
		LetItResume(this.Pid)
	}
	return nil
}

func (this *UretprobeEvent) Clone() IEventStruct {
	event := new(UretprobeEvent)
	return event
}

func (this *UretprobeEvent) GetUUID() string {
	s := fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
	if this.mconf.ShowTime {
		s = fmt.Sprintf("%d|%s", this.Ts, s)
	}
	if this.mconf.ShowUid {
		s = fmt.Sprintf("%d|%s", this.Uid, s)
	}
	return s
}

func (this *UretprobeEvent) MarshalJSON() ([]byte, error) {
	type ContextAlias config.ContextFields
	type UretprobeAlias config.UretprobeFields
	return json.Marshal(&struct {
		Event string `json:"event"`
		LR    string `json:"lr"`
		SP    string `json:"sp"`
		PC    string `json:"pc"`
		Comm  string `json:"comm"`
		*ContextAlias
		*UretprobeAlias
		Stack_str string `json:"stack_str"`
	}{
		Event:        "uretprobe",
		LR:           fmt.Sprintf("0x%x", this.LR),
		SP:           fmt.Sprintf("0x%x", this.SP),
		PC:           fmt.Sprintf("0x%x", this.PC),
		Comm:         util.B2STrim(this.Comm[:]),
		ContextAlias: (*ContextAlias)(&this.ContextFields),
		UretprobeAlias: (*UretprobeAlias)(&this.UretprobeFields),
		Stack_str:    this.Stack_str,
	})
}

func (this *UretprobeEvent) String() string {
	this.Stack_str = this.GetStackTrace("")

	if this.mconf.FmtJson {
		data, err := json.Marshal(this)
		if err != nil {
			panic(err)
		}
		return string(data)
	}

	var lr_str string
	var pc_str string
	if this.mconf.GetOff {
		lr_str = fmt.Sprintf("LR:0x%x(%s)", this.LR, this.GetOffset(this.LR))
		pc_str = fmt.Sprintf("PC:0x%x(%s)", this.PC, this.GetOffset(this.PC))
	} else {
		lr_str = fmt.Sprintf("LR:0x%x", this.LR)
		pc_str = fmt.Sprintf("PC:0x%x", this.PC)
	}

	var s string
	s = fmt.Sprintf("[%s] %s%s ret=0x%x %s %s SP:0x%x", this.GetUUID(), this.uprobe_point.Name, this.ArgStr, this.RetValue, lr_str, pc_str, this.SP)

	return s + this.Stack_str
}

