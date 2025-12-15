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

type UprobeEvent struct {
    ContextEvent
    UUID         string
    uprobe_point *config.UprobeArgs
    config.UprobeFields
    Stack_str string
}

func (this *UprobeEvent) DumpRecord() bool {
    return this.mconf.DumpRecord(common.UPROBE_EVENT, &this.rec)
}

func (this *UprobeEvent) ParseEvent() (IEventStruct, error) {
    data_e, err := this.ContextEvent.ParseEvent()
    if err != nil {
        panic("...")
    }
    if data_e == nil {
        if err := this.ParseContext(); err != nil {
            panic(fmt.Sprintf("UprobeEvent.ParseContext() err:%v", err))
        }
        return this, nil
    }
    return data_e, nil
}

func (this *UprobeEvent) ParseContext() (err error) {
    if this.EventId != UPROBE_ENTER && this.EventId != UPROBE_EXIT {
        panic(fmt.Sprintf("UprobeEvent.ParseContext() failed, EventId:%d", this.EventId))
    }

    // this.logger.Printf("ParseContext EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))

    this.ReadArg(&this.ProbeIndex)
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

    var results []string
    if this.EventId == UPROBE_ENTER {
        // 解析函数入口参数
        // 完全按照 syscall enter 的方式：使用 binary.Read 直接读取 Arg_reg 结构体
        // eBPF 保存格式：[index][value]，正好对应 Arg_reg 的 Index(uint8) + Address(uint64)
        for _, point_arg := range this.uprobe_point.PointArgs {
            var ptr argtype.Arg_reg
            if err := binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
                // 读取失败，说明没有更多参数了
                break
            }
            arg_fmt := point_arg.Parse(ptr.Address, this.buf, config.EBPF_UPROBE_ENTER)
            results = append(results, fmt.Sprintf("%s=%s", point_arg.Name, arg_fmt))
        }
    } else if this.EventId == UPROBE_EXIT {
        // 解析返回值：由 uretprobe_point_args 生成，ret 作为第一个“参数”写入 buffer
        if this.uprobe_point.RetArg != nil {
            var ret_reg argtype.Arg_reg
            if err := binary.Read(this.buf, binary.LittleEndian, &ret_reg); err == nil {
                ret_fmt := this.uprobe_point.RetArg.Parse(ret_reg.Address, this.buf, config.EBPF_UPROBE_EXIT)
                results = append(results, fmt.Sprintf("%s=%s", this.uprobe_point.RetArg.Name, ret_fmt))
            } else {
                results = append(results, "ret=<unavailable>")
            }
        } else {
            results = append(results, "ret=<unconfigured>")
        }

        // 解析入参（使用 entry 时保存的寄存器）
        for _, point_arg := range this.uprobe_point.PointArgs {
            var ptr argtype.Arg_reg
            if err := binary.Read(this.buf, binary.LittleEndian, &ptr); err != nil {
                break
            }
            arg_fmt := point_arg.Parse(ptr.Address, this.buf, config.EBPF_UPROBE_EXIT)
            results = append(results, fmt.Sprintf("%s=%s", point_arg.Name, arg_fmt))
        }
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

func (this *UprobeEvent) Clone() IEventStruct {
    event := new(UprobeEvent)
    return event
}

func (this *UprobeEvent) GetUUID() string {
    s := fmt.Sprintf("%d|%d|%s", this.Pid, this.Tid, util.B2STrim(this.Comm[:]))
    if this.mconf.ShowTime {
        s = fmt.Sprintf("%d|%s", this.Ts, s)
    }
    if this.mconf.ShowUid {
        s = fmt.Sprintf("%d|%s", this.Uid, s)
    }
    return s
}

func (this *UprobeEvent) MarshalJSON() ([]byte, error) {
    type ContextAlias config.ContextFields
    type UprobeAlias config.UprobeFields
    event_type := "uprobe"
    if this.EventId == UPROBE_EXIT {
        event_type = "uretprobe"
    }
    return json.Marshal(&struct {
        Event string `json:"event"`
        LR    string `json:"lr"`
        SP    string `json:"sp"`
        PC    string `json:"pc"`
        Comm  string `json:"comm"`
        *ContextAlias
        *UprobeAlias
        Stack_str string `json:"stack_str"`
    }{
        Event:        event_type,
        LR:           fmt.Sprintf("0x%x", this.LR),
        SP:           fmt.Sprintf("0x%x", this.SP),
        PC:           fmt.Sprintf("0x%x", this.PC),
        Comm:         util.B2STrim(this.Comm[:]),
        ContextAlias: (*ContextAlias)(&this.ContextFields),
        UprobeAlias:  (*UprobeAlias)(&this.UprobeFields),
        Stack_str:    this.Stack_str,
    })
}

func (this *UprobeEvent) String() string {
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
    event_prefix := ""
    if this.EventId == UPROBE_EXIT {
        event_prefix = "[RET] "
    }
    s = fmt.Sprintf("[%s] %s%s%s %s %s SP:0x%x", this.GetUUID(), event_prefix, this.uprobe_point.Name, this.ArgStr, lr_str, pc_str, this.SP)

    return s + this.Stack_str
}
