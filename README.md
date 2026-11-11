# Navicat Premium 18.0.6：从汇编分析到原生 Keypatch 的完整复现

本文从注册窗口的事件处理函数出发，逐步还原短序列号校验、请求码加密、激活响应验证和公钥构造，再将计算过程实现为 C++17 / Win32 原生窗口程序。

样本为 **Navicat Premium 18.0.6.0，Windows x64**。下文按“定位入口、还原算法、定位公钥、计算新参数、生成响应、编译工具”的顺序展开。需要执行的脚本和完整 C++ 代码都直接列在正文；示例姓名与设备值均为合成数据。

已验证的是汇编与文件指纹、公钥隔离模拟、数学关系、合成请求与响应，以及原生程序编译和自检；产品实际激活及重启后的状态仍需按文末步骤验证。

## 1. 准备样本并统一地址含义

准备未修改的 `navicat.exe`、`libcc.dll`、`libcf.dll`，以下读取样本的命令都在这三个文件所在位置执行。若已有补丁，应使用完整原版副本进行静态复现。

分析用 Python 3.12，安装所需库：

```powershell
python -m pip install pefile==2024.8.26 capstone==5.0.9 unicorn==2.1.4 cryptography==49.0.0 pycryptodome==3.23.0
```

另准备 x64 WinDbg 或 x64dbg 观察汇编。最后编译窗口程序需要 Visual Studio 的“使用 C++ 的桌面开发”工作负载和 Windows SDK。

### 1.1 先比对完整哈希

```powershell
Get-FileHash -LiteralPath .\navicat.exe, .\libcc.dll, .\libcf.dll -Algorithm SHA256
(Get-Item -LiteralPath .\navicat.exe).VersionInfo | Format-List FileVersion,ProductVersion
```

本次样本为：

| 文件        | SHA-256                                                            |
|-------------|--------------------------------------------------------------------|
| navicat.exe | `23e325a375a53b0443f6a29dd34e932ec0d89dc13ffc463c1a2fc3e07071212f` |
| libcc.dll   | `d34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207` |
| libcf.dll   | `a4e792cfd0f103033cc3495d737558850b7f4359347af643ccf6f14b534a486f` |

原版 `libcc.dll` 大小为 `158456392` 字节。工具会匹配完整 SHA-256，所以即使文件版本号相同，内容不同也会停止操作。

### 1.2 RVA、VA 和文件偏移要分清

本文的分析地址默认使用 **RVA**，即相对于所属模块基址的位置。

```text
运行时 VA = 当前进程中该模块的实际加载基址 + RVA
静态 VA   = PE 中记录的首选 ImageBase + RVA
```

本样本的首选基址：

```text
navicat.exe  0x00400000
libcc.dll    0x180000000
libcf.dll    0x180000000
```

两个 DLL 的首选基址相同，不代表运行时加载在同一地址。调试时用所属模块名加 RVA，避免混淆，也避免受到 ASLR 的影响。

文件偏移还需要经过所在节区转换：

```text
FileOffset = RVA - Section.VirtualAddress + Section.PointerToRawData
```

以后定位到 `libcc+0x27ED015` 时，不能直接把它当作磁盘文件偏移。这个区别会在补丁部分再次用到。

## 2. 从界面找入口：先辨认两条不同的校验路径

注册窗口里至少有两种输入：四组短序列号，以及手动激活窗口里的长字符串。它们的格式、调用链和意义都不同。

| 输入     | 典型长度                      | 主要处理                                          |
|----------|-------------------------------|---------------------------------------------------|
| 短序列号 | 去掉分组后 16 字符            | Base32 → 固定头 → DES → 字段检查                  |
| 请求码   | 本文样本为 344 个 Base64 字符 | 由 K、DI、P 等数据构造，再公钥加密                |
| 激活响应 | 本文实现为 344 个 Base64 字符 | Base64 → 公钥恢复 → 类型 1 填充 → JSON 与绑定检查 |

344 个 Base64 字符严格解码后得到 256 字节，与 2048 位 RSA 块相符。**长度本身只是格式线索**，RSA 的结论还要由虚表、类型信息和运算代码确认。

### 2.1 利用 Delphi 的窗体与方法元数据

主程序保留了 `TRegistrationSubForm` 和 `TManualActivationSubForm` 等名称。相比一开始全盘搜索密码常量，先利用控件和事件元数据更容易把用户动作和底层逻辑接起来。

四个序列号输入框的变更事件分别位于：

```text
navicat+0x98F0A0  edKey1Change
navicat+0x98F190  edKey2Change
navicat+0x98F340  edKey3Change
navicat+0x98F500  edKey4Change
```

它们进入共同检查函数 `navicat+0x98FFB0`。该函数依次读取窗体对象偏移 `+0x808/+0x810/+0x818/+0x820` 的四个输入框，拼接时不插入连字符，然后转换成 UTF-8。

`navicat+0x99014A` 比较总字节数与 `0x10`。达到 16 字节后，`navicat+0x99017E` 才调用 DLL 校验。返回的 `AL` 决定有效图标与按钮状态。这解释了为什么序列号在输入过程中就会给出反馈。

### 2.2 穿过按序号导出的 DLL 接口

界面看到的间接调用不会直接告诉我们算法名称，需要继续检查导出解析和注册的回调：

```text
navicat+0x98FFB0
  → navicat+0x99017E
  → libcc 导出 ordinal 0xA0EA，RVA 0x1C54980
  → 适配器 RVA 0x1E71170
  → libcc+0x2740320
  → 注册中心虚表 +0x30
  → libcc+0x2740530，返回整数状态
```

`libcc+0x2740320` 是包装层；真正的字段校验在 `+0x2740530`。核心返回 `0` 表示通过，包装层再转换成界面需要的布尔值。不能把内层和外层返回值的含义反过来。

在反汇编器中按上表检查事件方法、间接调用和导出地址；第 5 节的正文脚本还会直接打印所用导出序号和关键虚表槽。

## 3. 从汇编还原短序列号

### 3.1 归一化和 Base32

核心函数先对字符进行归一化：`8 → I`、`9 → O`；Base32 解码器还会将 ASCII 小写转为大写。

正常字符表为：

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
```

16 个字符总共携带 `16 × 5 = 80` 位，即 10 字节。汇编在 `libcc+0x2740675` 检查解码长度必须等于 10，接着在 `+0x274068C/+0x27406A1` 检查开头两个字节为：

```text
68 2A
```

因此解码结果的结构已经缩小为：

```text
68 2A | 8 字节待解密数据
```

### 3.2 为什么判断为 DES-ECB

`libcc+0x27406E8` 调用安全服务，实际落到 `libcf+0xF9BC0`。这里使用 8 字节密钥；相关 RTTI 包含 `DES::Base`、解密方向的 `BlockCipherFinal<false,...>` 和 `ECB_OneWay`。

把“块长 8 字节”“密钥 8 字节”“RTTI 类型”“调用方向”放在一起，才形成 DES-ECB 解密的证据。单看一个 8 字节常量还不够。

本样本的密钥位于 `libcc+0x8051568`，按内存字节顺序读取为：

```text
E9 7F B0 60 77 45 90 AE
```

这里按字节使用，不把反汇编里显示的 64 位小端立即数直接当成同顺序的密钥文本。

### 3.3 明文每个字节做什么

将后 8 字节 DES 密文解开，得到 `p0 ... p7`。从比较、移位和查表代码可以归纳出：

| 字节       | 当前已确认的用途                                       |
|------------|--------------------------------------------------------|
| p0、p1、p2 | 在该校验核心正常路径中没有独立比较，生成时作为随机前缀 |
| p3、p4     | 与产品提供者值 P 组合查询产品元组表                    |
| p5         | 和变体标志 E 一起决定内部值 M                          |
| p6 高四位  | `V = (p6 >> 4) + 16`，当前校验要求 `V >= 18`           |
| p6 低四位  | 单独保存；本文固定为 0，不额外猜测业务名称             |
| p7         | 映射为内部许可证类别 Ctype                             |

表中的 P、E 必须继续追踪。包装函数没有回调时的默认值，不能代替当前程序初始化之后的值。

### 3.4 从主程序回调确认 P=3、E=false

主程序把回调通过导出 ordinal `0xF621` 注册进 `libcc.dll`。静态追踪得到：

| 参数 | DLL 保存位置    | 主程序回调        | 关键机器码                               |
|------|-----------------|-------------------|------------------------------------------|
| P    | libcc+0x8CEDD88 | navicat+0x2DBECE0 | `B8 03 00 00 00 C3`，即 `mov eax,3; ret` |
| E    | libcc+0x8CEDCC8 | navicat+0x2DBEEB0 | `33 C0 C3`，即 `xor eax,eax; ret`        |

注册函数在 `libcc+0x1C546D0`。追踪栈上传参时，还要算上 `call` 压入的返回地址和函数序言调整。本例 DLL 序言后栈指针比调用前低 `0x30`，所以不能把 DLL 中的 `[rsp+0xB0]` 直接当作主程序调用前的同一偏移。

这一步的结论来自文件中固定回调的注册关系；本次没有读取运行进程中的两个槽来做动态确认。

### 3.5 选定当前工具使用的字段组合

P=3 时，产品表 A 的对应值为 `p4=0x32`、`p3=0xCE`；E=false 时，选择 `p5=0x65` 可得到内部值 M=1。再取 `p6=0x20`，可得 V=18、低四位为 0；`p7=0xFF` 映射到 Ctype=2。

于是工具固定使用：

```text
随机 3 字节 | CE 32 65 20 FF
```

这是从当前样本中选取的一组可通过静态字段检查的配置。工具没有把所有字段扩展成可选项，也不凭 Ctype 的数字给它附会上未经确认的商业名称。

反向生成的步骤是：

```text
8 字节明文
  → DES-ECB 加密，不填充
  → 在密文前加 68 2A
  → 标准 Base32 编码
  → 得到 16 字符序列号
```

独立固定样本如下，可用于核对每一步：

```text
明文：DB B7 82 CE 32 65 20 FF
DES 密文：2D 74 15 ED EE FF 83 B4
Base32 前的数据：68 2A 2D 74 15 ED EE FF 83 B4
Base32：NAVC25AV5XXP7A5U
分组显示：NAVC-25AV-5XXP-7A5U
```

另一个前缀 `58 9D D8` 对应 `NAVBHVSV4IIE2UKR`。这些是算法测试向量，不代表已经完成产品授权。

下面直接复核固定样本：

\<!-- runnable:serial --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
import base64
from Crypto.Cipher import DES

key = bytes.fromhex('E97FB060774590AE')
plain = bytes.fromhex('DBB782CE326520FF')
cipher = DES.new(key,DES.MODE_ECB).encrypt(plain)
decoded = bytes.fromhex('682A') + cipher
serial = base64.b32encode(decoded).decode('ascii')
assert cipher.hex() == '2d7415edeeff83b4'
assert serial == 'NAVC25AV5XXP7A5U'
assert DES.new(key,DES.MODE_ECB).decrypt(base64.b32decode(serial)[2:]) == plain
print('plain:',plain.hex(' '))
print('cipher:',cipher.hex(' '))
print('decoded:',decoded.hex(' '))
print('serial:',serial)
'@ | python -
```

## 4. 再追“激活”按钮：长响应怎么被检查

### 4.1 窗体成员与调用链

`TManualActivationSubForm` 中的两个文本控件分别是：

```text
meRequestCode     窗体对象 +0x7E8
meActivationCode  窗体对象 +0x7F0
当前序列号文本    窗体对象 +0x810
```

`navicat+0x96DD10` 的准备显示逻辑会保存序列号并取得请求码。按钮事件是 `navicat+0x96D970`：它在 `+0x96DA46` 读取下方的激活响应，之后将序列号和响应转换为 UTF-8，调用 DLL 导出。

```text
navicat+0x96D970                    btOKClick
  → navicat+0x96DAC8                间接调用
  → libcc ordinal 0xE6B5
  → libcc+0x1C55000                 包装 std::string / 适配器
  → libcc+0x1E71334
  → libcc+0x2746930                 manualActivate
  → libcc+0x2746B0E，虚表 +0x38
  → libcc+0x273F9E0                 checkActivationData
```

在 WinDbg 中可以沿模块名加 RVA 查看关键位置：

```text
u navicat+0x96d970
u navicat+0x96dac8
u libcc+0x1c55000
u libcc+0x2746930
dq libcc+0x749aa98+0x38 L1
u libcc+0x273f9e0
```

其中 `dq` 读取虚表槽中的函数地址，随后用 `u` 检查目标。要观察实际按钮调用，可以在 `navicat+0x96D970` 或 `libcc+0x2746B0E` 下断点；下面的结论仍区分静态路径和实际动态观察。

### 4.2 虚表调用要先确定对象类型

在 `libcc+0x2746B0E` 看到的实际指令是：

```asm
02746b0e  FF 50 38  call qword ptr [rax + 38h]
02746b11  85 C0     test eax, eax
02746b13  74 5D     je   成功后的后续比较
```

`+0x38` 只表示槽偏移，不能据此给函数命名。这里通过注册中心的虚表 `libcc+0x749AA98`，确认该槽指向 `libcc+0x273F9E0`。

进入检查函数后，在 `+0x273FAE9` 看到：

```asm
call qword ptr [rax + 0B8h]
```

这一次的对象属于安全服务。`CSSecurityCenter` 与 Windows 实现的虚表中，`+0xB8` 均指向 `libcf+0xFCD50`，再转到 `+0xFCD90`。同样是虚表调用，但这次的槽属于另一类对象。

### 4.3 Base64 的结论来自类型信息

`manualActivate` 先过滤输入。对应区间为 `libcc+0x27469F4 ... +0x2746A8A`，有符号字节比较会保留 `0x20 < b < 0x80` 的字节。正常 ASCII Base64 中的空格、换行等会被去掉。

接着，`libcc+0x2746A9D` 调用数据转换服务虚表 `+0xD8`。该槽指向 `libcf+0x39FB0`，构造对象的 RTTI 为 `CryptoPP::Base64Decoder`。这使“Base64 解码”有了直接类型证据。

独立工具对 Base64 使用严格、规范的检查，不承诺与 Crypto++ 对所有畸形编码的宽容行为完全一致。

### 4.4 公钥消息恢复的证据

`libcf+0x22BCD0` 保存的函数签名是：

```cpp
CSSecurityCenter::decrypt_RSA_NON_STD(
    const std::string&, STSecurityRSAPublicKey*, bool)
```

签名明确使用 `STSecurityRSAPublicKey`。再结合内部的大整数运算，可把正常 256 字节响应解释为大端整数 S，执行：

```text
R = S^e mod N
e = 65537
```

这里要恢复出消息本身。普通 `RSA-SHA256` 验签 API 往往期待哈希的 DigestInfo 结构，与本路径期待的 JSON 消息不是同一种接口。

### 4.5 类型 1 填充怎样从比较指令看出来

在 `libcf+0xFD24C ... +0xFD28F` 有以下实际检查：

```asm
cmp byte ptr [rax], 1
jne 填充失败
...
cmp byte ptr [rcx + rax], 0FFh
jne 停止扫描
inc ebx
...
cmp ebx, 8
jle 填充失败
...
cmp byte ptr [rcx + rax], 0
jne 填充失败
```

完整 256 字节表示必须是：

```text
00 01 FF FF ... FF 00 JSON
      至少 8 个 FF
```

反汇编中的首字节比较是 `01`，原因是内部最短大整数表示已经省去了固定宽度表示最前面的 `00`。实现独立算法时，需要重新补回 256 字节，不能从上述比较推导成以 `01` 开头的 256 字节块。

调用方在 `libcf+0xFCD68` 将第 5 个参数设为 true，`+0xFD209` 根据该参数决定是否进入填充分支。直接反汇编这两处，可以确认激活路径确实启用了检查。

只在被调用函数里找到一个填充分支，还不能证明当前激活路径一定使用它。

## 5. 用完整脚本核对导出、虚表与关键指令

下面这段代码只读三个 PE 文件，先校验完整哈希，再打印关键指令、导出、虚表、DES 常量与补丁偏移。它不加载或执行目标 DLL，不需要其他辅助脚本。

\<!-- runnable:pe --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
from pathlib import Path
import hashlib, struct
import pefile, capstone

specs = {
 'navicat.exe':('23e325a375a53b0443f6a29dd34e932ec0d89dc13ffc463c1a2fc3e07071212f',
               [(0x99014A,0x3C),(0x96DAC8,2),(0x2DBECE0,6),(0x2DBEEB0,3)]),
 'libcc.dll':('d34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207',
             [(0x2746B0E,7),(0x273FAE9,6),(0x2744AEC,0x1B),(0x27ED014,0x16)]),
 'libcf.dll':('a4e792cfd0f103033cc3495d737558850b7f4359347af643ccf6f14b534a486f',
             [(0xFD24C,0x45),(0xFCD68,5)])
}
for name,(expected,spans) in specs.items():
    raw = Path(name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, name+' build mismatch'
    pe = pefile.PE(data=raw,fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    print('\nMODULE',name,'base',hex(base))
    for rva,size in spans:
        for ins in decoder.disasm(pe.get_data(rva,size),base+rva):
            print(f'{ins.address-base:08x} {ins.bytes.hex(" "):30} {ins.mnemonic} {ins.op_str}')
    if name == 'libcc.dll':
        pe.parse_data_directories(directories=[0])
        for ordinal in (0xA0EA,0xE6B5,0xCE89,0xF621):
            entry = next(x for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.ordinal == ordinal)
            print('ordinal',hex(ordinal),'->',hex(entry.address))
        for table,slot in [(0x749AA98,0x38),(0x748E358,0x30)]:
            target = struct.unpack('<Q',pe.get_data(table+slot,8))[0]-base
            print('vtable',hex(table),'slot',hex(slot),'->',hex(target))
        print('DES bytes:',pe.get_data(0x8051568,8).hex(' '))
        offset = pe.get_offset_from_rva(0x27ED015)
        print('patch file offset:',hex(offset))
        assert offset == 0x27EC415
'@ | python -
```

预期导出和虚表结果包括：

```text
ordinal 0xa0ea -> 0x1c54980
ordinal 0xe6b5 -> 0x1c55000
ordinal 0xce89 -> 0x1c551f0
ordinal 0xf621 -> 0x1c546d0
vtable 0x749aa98 slot 0x38 -> 0x273f9e0
vtable 0x748e358 slot 0x30 -> 0x27e3bc0
DES bytes: e9 7f b0 60 77 45 90 ae
patch file offset: 0x27ec415
```

脚本展示的是已定位位置的复核方法。最初定位仍从窗体方法名、导出解析、错误字符串交叉引用和接收对象类型逐层进行；不能把相同的槽偏移直接解释成相同接口。

## 6. JSON、绑定与错误码

### 6.1 从解析调用确认恢复内容是 JSON

`libcc+0x273FB30` 调用 JSON 服务。对应实现 `libcf+0xC3410` 失败时使用字符串 `Not a valid JSON.`。检查函数先预置返回状态 1，再测试解析结果；失败会沿清理路径返回这个状态。

后面的类型谓词来自 `COJsonValue`：字符串检查涉及 RapidJSON 标志 `0x400`；有符号 64 位整数检查涉及 `0x80`。根据每次访问的字段名和类型谓词，可以整理出：

| 字段 | 当前激活数据解析函数的规则                               |
|------|----------------------------------------------------------|
| K    | 必须是字符串；之后与界面当前序列号按 UTF-8 字节比较      |
| N    | 必须是字符串；此处没有要求非空                           |
| O    | 必须是字符串；此处没有要求非空                           |
| T    | 必须是有符号 64 位 JSON 整数                             |
| M    | 是字符串就提取，否则保持空字符串                         |
| DI   | 是字符串就提取，否则保持空字符串；之后与提供者设备值比较 |
| FA   | 是有符号 64 位整数就提取，否则保持 0                     |

`T` 不能写成字符串、布尔值或 `1.0` 这样的浮点表示。解析函数没有直接比较当前时间，并不意味着后续状态路径没有时间限制。

### 6.2 K 和 DI 是两个独立的后续比较

解析通过后，`manualActivate` 继续执行：

```text
恢复的 K  == 界面保存的当前序列号
恢复的 DI == 当前提供者取得的设备值
```

K 的比较发生在 `libcc+0x2746B72 ... +0x2746BA5`；DI 的取得和比较发生在 `+0x2746BAB ... +0x2746C33`。

因此，工具可以用去分隔符、转大写后的值检查“用户有没有填错序列号”，但构造响应时仍要保留请求中的 **原始 K 文本**，不能擅自改写其大小写或连字符。DI 同样应当逐字节保留。

### 6.3 为什么不在工具中猜测设备算法

提供者的 `libcc+0x27E1D30` 会调用 `+0x27E1FF0`、`+0x27E27E0`，再截取前 `min(20,长度)` 字节。末段涉及 MD5 和文本转换，但输入依赖平台服务、本地持久值和注册表数据，尚未全部还原。

因此，当前工具直接从新请求的 JSON 中取得 DI。请求由原程序生成，其中已经含有原程序当前使用的设备值；外部工具无需重复实现尚未确认的上游算法。

### 6.4 按执行阶段理解错误码

| 显示结果     | 直接对应的阶段                                                        |
|--------------|-----------------------------------------------------------------------|
| `90030001-1` | RSA 处理后，恢复内容未能成功打开/解析；填充失败也可能使这里面对空结果 |
| `90030001-2` | 解析后的内部 JSON 有效标志检查失败                                    |
| `90030001-3` | 必需字段或字段类型不符合                                              |
| `90030002`   | K 与当前序列号不一致                                                  |
| `90030003`   | DI 与当前提供者值不一致                                               |
| `90030004`   | 当前用户保存位置打开/创建失败                                         |

错误编号可以帮助定位已执行到哪个阶段，但仅凭 `90030001-1` 无法区分截断、错误密钥、错误填充和无效 JSON。需要配合实际输入和中间值。

请求码和响应即使都为 344 个 Base64 字符，也不能相互替代。第 12 节的完整闭环示例会直接把请求当作响应计算，观察类型 1 填充不成立。

## 7. 追踪验证公钥的来源

### 7.1 从被使用的密钥对象向初始化回溯

激活数据检查使用注册中心对象 `+0x20` 的密钥对象。沿该成员的写入回溯，可以看到：

```text
libcc+0x2744AF7
  → 提供者虚表 +0x30，取得公钥字符串
  → 安全服务虚表 +0x68，导入公钥
libcc+0x2744B03
  → 将导入结果写入注册中心对象 +0x20
```

`CSRegistrationInfoFetcher_WIN` 的虚表在 `libcc+0x748E358`，`+0x30` 指向 `libcc+0x27E3BC0`。这就是公钥字符串构造函数。

这样定位有一个好处：拿到的是验证路径实际引用的密钥来源，避免把安装文件中其他用途的 RSA 类型、证书或配置密钥误认成激活密钥。

### 7.2 公钥不是一整块可直接搜索的裸 N

构造函数范围很长，从 `+0x27E3BC0` 到 `+0x27F791E`，包含碎片拼接和条件分支。某些片段在数据区，另一些字符来自指令立即数。

因此，在文件里搜索 PEM 头或完整 Base64 公钥可能一无所获。需要恢复这段代码执行后的最终字符串，而不能把找到的一段 `Qa` 或一个 `S` 直接认作完整公钥。

### 7.3 用有限模拟替代原生加载整个 DLL

可以用有界模拟完成以下工作：

1.  先验证原版 DLL 的完整 SHA-256。
2.  用 pefile 取得内存映像，映射到 Unicorn 私有地址空间。
3.  为栈、堆和返回停止位置分别建立模拟内存。
4.  仅允许执行公钥构造函数及有限辅助函数范围。
5.  为 C++ 字符串赋值、追加、字符追加等帮助函数提供替代实现。
6.  设置 500000 条指令上限；只有正常返回到停止位置才接受结果。
7.  将结果按 Base64 解码，再交给独立密码库解析为 RSA 公钥。

字符串对象的关键布局是 MSVC x64 `std::string`：长度位于对象 `+16`，容量位于 `+24`；容量大于 15 时，首指针指向外部数据，否则数据内联于对象起始处。

模拟器针对 `libcc+0x1BC8470` 的处理本质上是：

```python
current = string_data(rcx)
character = bytes([rdx & 0xff])
put_string(rcx, current + character)
```

这会在后面追踪字符 S 时用到。Windows x64 中，整数/指针前四个参数通常在 RCX、RDX、R8、R9；这里 DL 正好是 RDX 的低 8 位。

下面给出完整模拟代码。它会分别模拟原始映像和只在模拟内存修改的映像，每种都用 0 与 A5 两种初始栈。磁盘样本不作修改。

\<!-- runnable:emulator --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
import base64
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_RSP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

EXPECTED = 'd34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207'

def recover_public_key(stack_fill=0, patched=False):
    path = Path('libcc.dll')
    with path.open('rb') as handle:
        if hashlib.file_digest(handle, 'sha256').hexdigest() != EXPECTED:
            raise ValueError('Unsupported libcc.dll build')
    pe = pefile.PE(str(path), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    image_size = (pe.OPTIONAL_HEADER.SizeOfImage+0xfff) & ~0xfff
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, image_size)
    mapped = bytearray(pe.get_memory_mapped_image())
    assert mapped[0x27ED015] == 0x53
    if patched:
        mapped[0x27ED015] = 0x54
    uc.mem_write(base, bytes(mapped))
    uc.mem_protect(base, image_size, UC_PROT_READ | UC_PROT_EXEC)
    stack, heap, stop = 0x10000000, 0x20000000, 0x30000000
    uc.mem_map(stack, 0x200000)
    uc.mem_write(stack, bytes([stack_fill])*0x200000)
    uc.mem_map(heap, 0x2000000)
    uc.mem_map(stop, 0x1000)
    cursor = heap+0x1000
    buffers = {}

    def qword(address):
        return struct.unpack('<Q', uc.mem_read(address, 8))[0]

    def string_data(address):
        length, capacity = struct.unpack('<QQ', uc.mem_read(address+16, 16))
        if length > 4095:
            raise ValueError('Unexpected string length')
        return bytes(uc.mem_read(qword(address) if capacity > 15 else address, length))

    def cstring(address):
        return bytes(uc.mem_read(address, 4096)).split(b'\0')[0]

    def put_string(address, value):
        nonlocal cursor
        if len(value) > 4095:
            raise ValueError('Unexpected key-builder string size')
        if address not in buffers:
            if cursor+4096 > heap+0x2000000:
                raise ValueError('Emulator heap exhausted')
            buffers[address] = cursor
            cursor += 4096
        dest = buffers[address]
        uc.mem_write(dest, value+b'\0')
        uc.mem_write(address, struct.pack('<QQQQ', dest, 0, len(value), 4095))

    stubs = {0x1ba6b30, 0x1ba6a90, 0x1ba6a80, 0x1ba6b20,
             0x1bc8470, 0x1ba6970, 0x1ba7890, 0x1d3bd30, 0x4533620}
    instructions = 0
    trace = []

    def hook(machine, address, size, _):
        nonlocal instructions
        instructions += 1
        rva = address-base
        if rva not in stubs:
            if not (0x27e3570 <= rva < 0x27e3bbf or 0x27e3bc0 <= rva < 0x27f791e or
                    0x1bc8420 <= rva < 0x1bc8433 or 0x1ba68b0 <= rva < 0x1ba68bf):
                raise ValueError(f'Execution outside the allowed key-builder code: {rva:#x}')
            return
        rcx, rdx, r8, r9 = (machine.reg_read(reg) for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9))
        if rva == 0x1ba6b30:
            put_string(rcx, cstring(rdx))
        elif rva == 0x1ba6a90:
            put_string(rcx, string_data(rcx)+string_data(rdx))
        elif rva == 0x1ba6a80:
            put_string(rcx, string_data(rcx)+cstring(rdx))
        elif rva == 0x1bc8470:
            current = string_data(rcx)
            if len(current) == 364:
                trace.append({'index':len(current), 'character':chr(rdx & 255),
                    'call_rva':hex(qword(machine.reg_read(UC_X86_REG_RSP))-5-base)})
            put_string(rcx, current+bytes([rdx & 255]))
        elif rva == 0x1ba6970:
            if r8 > 4095:
                raise ValueError('Unexpected append length')
            put_string(rcx, string_data(rcx)+bytes(machine.mem_read(rdx, r8)))
        elif rva == 0x1d3bd30:
            if rdx > 4095:
                raise ValueError('Unexpected repeat length')
            put_string(rcx, string_data(rcx)+bytes([r9 & 255])*rdx)
        # Destruction, deallocation and stack probing have no observable result
        # needed here. The latter must preserve RAX (the requested stack size).
        if rva != 0x4533620:
            machine.reg_write(UC_X86_REG_RAX, rcx)
        rsp = machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RIP, qword(rsp))
        machine.reg_write(UC_X86_REG_RSP, rsp+8)

    uc.hook_add(UC_HOOK_CODE, hook)
    rsp = stack+0x1fff08
    uc.mem_write(rsp, struct.pack('<Q', stop))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RDX, heap)
    uc.emu_start(base+0x27e3bc0, stop, count=500000)
    if uc.reg_read(UC_X86_REG_RIP) != stop:
        raise ValueError('Key-builder did not return within the instruction limit')
    encoded = string_data(heap)
    der = base64.b64decode(encoded, validate=True)
    key = serialization.load_der_public_key(der)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError('Recovered object is not an RSA public key')
    return encoded, key, instructions, trace

results = {}
for patched in (False,True):
    previous = None
    for fill in (0,0xA5):
        encoded,key,count,trace = recover_public_key(fill,patched)
        assert count == 4553
        if previous is not None:
            assert encoded == previous
        previous = encoded
        der = key.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
        expected = ('45251890573bdf84afbd7b2d72f02f47bcad842e0a35b68ff9bab93cb0d9d472'
                    if patched else
                    '91a27375ba0199d4460e9d2216f5c68991c6004e074ff46fa93f6c59e934c124')
        assert hashlib.sha256(der).hexdigest() == expected
        assert trace == [{'index':364,'character':'T' if patched else 'S','call_rva':'0x27ed019'}]
        print(json.dumps({'patched':patched,'stack_fill':hex(fill),
            'instructions':count,'bits':key.key_size,'e':key.public_numbers().e,
            'spki_sha256':expected,'append':trace}))
    results[patched] = previous
assert results[False][364:365] == b'S'
assert results[True] == results[False][:364]+b'T'+results[False][365:]
print('original public key:',results[False].decode('ascii'))
'@ | python -
```

预期四次运行均正常返回，分别执行 4553 条指令。追加日志应为：

```text
原始映像：index=364, character=S, call_rva=0x27ed019
修改映像：index=364, character=T, call_rva=0x27ed019
```

原公钥 SPKI DER 的 SHA-256 为：

```text
91a27375ba0199d4460e9d2216f5c68991c6004e074ff46fa93f6c59e934c124
```

修改后的值为：

```text
45251890573bdf84afbd7b2d72f02f47bcad842e0a35b68ff9bab93cb0d9d472
```

两种初始栈输出一致，用于发现对未初始化栈字节的意外依赖；它不意味着整个 DLL 的所有行为都已模拟。

## 8. 从最终公钥的一个字符追到文件里的一个字节

### 8.1 找到确实执行过的字符追加

在原公钥构造的实际模拟路径中，字符串先拼接到 `CXJRHOFHSf1gzXWabR`，接着追加字符 S。对应原始指令为：

```asm
; 左侧地址是 libcc.dll 的 RVA
027ed014  B2 53                 mov dl, 53h
027ed016  49 8B CF              mov rcx, r15
027ed019  E8 52 B4 3D FF        call libcc+1BC8470h
```

解释每一条：

1.  `53h` 是 ASCII `S`，放入第二个参数的低字节 DL。
2.  RCX 取得待追加的字符串对象地址。
3.  调用已经辨认出的字符追加帮助函数。

因此候选修改落在第一条指令的**立即数**，不是操作码：

```text
B2 53 → B2 54
   S       T
```

可以用 `u libcc+0x27ed014` 查看该处，或用第 5 节的完整脚本打印相同机器码。

### 8.2 换算到磁盘文件偏移

本地址位于 `.text` 节：

```text
Section.VirtualAddress    = 0x1000
Section.PointerToRawData  = 0x0400
立即数 RVA                = 0x27ED015

文件偏移 = 0x27ED015 - 0x1000 + 0x400
         = 0x27EC415
```

所以当前版本的补丁规格是：

| 项目       | 值        |
|------------|-----------|
| 文件       | libcc.dll |
| 指令 RVA   | 0x27ED014 |
| 立即数 RVA | 0x27ED015 |
| 文件偏移   | 0x27EC415 |
| 原字节     | 0x53      |
| 新字节     | 0x54      |

### 8.3 Base64 字符怎么影响模数

原公钥 Base64 一共 392 字符。按从 0 开始的下标，位置 364 为 `S`。周围片段变化如下：

```text
原：FHSf1gzXWabRSvmt1nrl7sW6cjxl
新：FHSf1gzXWabRTvmt1nrl7sW6cjxl
```

将完整新文本 Base64 解码为 SPKI DER，再解析其中的 RSA 模数，可以发现：

```text
DER 从 0 起第 273 字节：        0x4A → 0x4E
256 字节大端模数第 240 字节：  0x4A → 0x4E
公钥指数仍为：                65537
模数位数仍为：                2048
```

DER 包含 ASN.1 标签、长度、算法标识和 INTEGER 符号补零，所以 DER 下标不等于模数下标；这里是解析结果给出的对应关系。

对 256 字节大端整数，第 240 字节的权重为 `256^(255-240)`，因此：

```text
N′ - N = (0x4E - 0x4A) × 256^15
       = 4 × 256^15
       = 2^122
```

整个链条现在才闭合：

```text
磁盘指令立即数 53 → 54
  → 执行时追加字符 S → T
  → 完整公钥 Base64 第 364 字符变化
  → DER 第 273 字节变化
  → 大端模数第 240 字节变化
  → N′ = N + 2^122
```

这也是为什么不能仅凭“公钥里找到一个 S”就下补丁。字符必须确实参与最后使用的密钥构造。

## 9. 为什么改变一个字符后能够求出私有指数

仅有原公钥 N 和 e，并没有提供原私有指数 d。这里改变的是验证端将使用的模数 N′，随后对这个新整数寻找可用的分解。

候选搜索有两种数学条件：N′ 本身通过素性测试时可使用 N′−1；或者 N′ 可以分解成互异素数 p、q 时，使用 `(p−1)(q−1)`。本文固定候选使用第二条。

第 7 节的字符追加日志指出，最终 Base64 从 0 起第 364 字符来自可独立替换的立即数。可以对该位置枚举其他 Base64 字符，每次解析出模数，再试除小素数。`S→T` 是其中一个可用候选。下面直接复核这个候选的试除过程：

\<!-- runnable:candidate --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
import base64, math
from cryptography.hazmat.primitives import serialization
from Crypto.Util.number import isPrime
PUBLIC_BASE64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I'
    'qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv'
    'a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF'
    'R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2'
    'WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt'
    'YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ'
    'awIDAQAB'
)

original = serialization.load_der_public_key(base64.b64decode(PUBLIC_BASE64)).public_numbers()
candidate = PUBLIC_BASE64[:364]+'T'+PUBLIC_BASE64[365:]
public = serialization.load_der_public_key(base64.b64decode(candidate)).public_numbers()
# A trial-division search over small odd primes, independent of an external patcher.
for p in range(3,2000,2):
    if not isPrime(p) or public.n % p:
        continue
    q = public.n // p
    if q != p and isPrime(q) and math.gcd(public.e,(p-1)*(q-1)) == 1:
        print('factor:',p,'q bits:',q.bit_length())
        assert p == 47
        break
else:
    raise AssertionError('No usable small-prime factor found')
assert original.n % 47 == 13
assert pow(2,122,47) == 34
'@ | python -
```

输出应为 `factor: 47 q bits: 2043`。这里寻找的是新模数的一个小因子，不是通用的 2048 位整数分解。

## 10. 独立计算新模数和私有指数

### 10.1 当前候选的分解关系

对上述 N′ 进行复核：

```text
p = 47
q = N′ / 47
q 的位数 = 2043
q 通过独立库的素性测试
gcd(65537, (47-1)×(q-1)) = 1
```

一个有助于理解的余数关系是：

```text
N mod 47       = 13
2^122 mod 47   = 34
N′ mod 47      = (13 + 34) mod 47 = 0
```

原 N 并没有因此被分解；发生变化的是验证程序将要使用的那个整数。

### 10.2 计算 D 的条件和含义

若 p、q 是互异素数，则：

```text
φ(N′) = (p - 1)(q - 1)
D = e^(-1) mod φ(N′)
eD mod φ(N′) = 1
```

q 的素性在本次复现中采用独立库检测，通过检测不表述为形式化素数证明。本文固定参数还经过多组整数运算对照和 CNG 公钥回验。

利用这个 D，工具可以计算 `x^D mod N′`。当验证端仍使用旧 N 时，这个结果不会满足旧公钥所要求的关系；只有两端参数一致，后续块结构和字段检查才有意义。

### 10.3 完整参数计算代码

下方完整列出原公钥 Base64，代码无需读取先前脚本的输出，也不写中间文件。运行后打印新模数 N′ 与私有指数 D 的完整十六进制值，C++ 示例中使用的固定参数由同一公式得到。

\<!-- runnable:profile --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
import base64, hashlib, json, math
from cryptography.hazmat.primitives import serialization
from Crypto.Util.number import isPrime
PUBLIC_BASE64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I'
    'qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv'
    'a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF'
    'R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2'
    'WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt'
    'YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ'
    'awIDAQAB'
)

assert len(PUBLIC_BASE64) == 392 and PUBLIC_BASE64[364] == 'S'
original_der = base64.b64decode(PUBLIC_BASE64, validate=True)
original = serialization.load_der_public_key(original_der).public_numbers()
changed = PUBLIC_BASE64[:364] + 'T' + PUBLIC_BASE64[365:]
der = base64.b64decode(changed, validate=True)
public = serialization.load_der_public_key(der).public_numbers()
n, e = public.n, public.e
p = 47
assert n % p == 0
q = n // p
assert p != q and isPrime(p) and isPrime(q)
phi = (p-1)*(q-1)
assert math.gcd(e, phi) == 1
d = pow(e, -1, phi)
assert e*d % phi == 1
assert n - original.n == 1 << 122
diff = [(i,a,b) for i,(a,b) in enumerate(zip(
    original.n.to_bytes(256,'big'), n.to_bytes(256,'big'))) if a != b]
assert diff == [(240, 0x4A, 0x4E)]
assert hashlib.sha256(der).hexdigest() == (
    '45251890573bdf84afbd7b2d72f02f47bcad842e0a35b68ff9bab93cb0d9d472')
for value in [0,1,47,n-1,n-47,19,123456789]:
    assert pow(pow(value,d,n),e,n) == value
print('p =',p,'; q bits =',q.bit_length())
print('modulus diff =',diff)
print('N mod 47 =',original.n % 47)
print('new N mod 47 =',n % 47)
print('inverse and round trips: passed')
print('N =',n.to_bytes(256,'big').hex())
print('D =',d.to_bytes(256,'big').hex())
'@ | python -
```

关键输出应包含 `p = 47 ; q bits = 2043`、`modulus diff = [(240, 74, 78)]`，以及逆元和往返检查通过。74、78 分别是十进制的 0x4A、0x4E。

### 10.4 为什么直接使用模幂

p=47、q 为 2043 位，是极不平衡的因子结构。某些私钥导入器会限制因子长度或私钥结构。因此原生程序直接计算 `x^D mod N′`，公钥方向另用 Windows CNG 进行独立回验，不依赖外部私钥文件或某个 PEM 导出器。

## 11. 确认磁盘偏移与补丁结果

第 7 节已经在模拟映像中执行原构造逻辑，证明修改后得到的公钥与数学候选一致。还应核对：RVA 换算后的文件偏移是否正确，整个文件修改后是否只有预期结果。

下面只修改内存中的文件副本，打印结果，不写回 DLL：

\<!-- runnable:memory --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
from pathlib import Path
import hashlib
import pefile

raw = Path('libcc.dll').read_bytes()
assert hashlib.sha256(raw).hexdigest() == (
    'd34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207')
pe = pefile.PE(data=raw,fast_load=True)
offset = pe.get_offset_from_rva(0x27ED015)
assert offset == 0x27EC415 and raw[offset] == 0x53
changed = bytearray(raw)
changed[offset] = 0x54
result = hashlib.sha256(changed).hexdigest()
assert result == 'bfae31129cfc21d84295f667a7efe85ad96d5575211664105b969b228ef192a1'
print('offset:',hex(offset))
print('patched-copy SHA256:',result)
print('disk file unchanged')
'@ | python -
```

结果应为偏移 `0x27EC415`，补丁版 SHA-256 为 `bfae31129cfc21d84295f667a7efe85ad96d5575211664105b969b228ef192a1`。这样，文件字节、模拟构造结果和解析出的模数三者建立了对应关系。

## 12. 同一把公钥承担两个方向的工作

现在可以把请求和响应的数学关系完整写出来。

### 12.1 请求方向：用公钥把请求数据送出去

请求生成入口是 `libcc+0x2747140`，已确认构造包含 K、DI、P 的 JSON，经过安全组件 `+0x98` 公钥加密，再 Base64 编码。

对于本文处理的类型 2 请求，结构为：

```text
RequestEM = 00 02 PS 00 RequestJSON
```

PS 至少 8 字节，且其中每个字节都非零。把块作为大端整数 m，计算：

```text
c = m^e mod N′
RequestCode = Base64(c 的固定 256 字节大端表示)
```

原程序请求侧的公钥调用关系有静态证据；当前类型 2 解密实现另经独立库产生的合成请求验证。本次尚未采集补丁后的真实产品请求完成动态对照，因此实际请求兼容性仍需要文末的产品实验补足。

外部工具拿到请求后计算：

```text
m = c^D mod N′
```

补回 256 字节，检查 `00 02`、非零填充和分隔符，再解析 JSON。从中保留原始 K 和 DI。

如果请求是在原 N 下生成的，换成新 D 和 N′ 计算通常只会得到不符合填充的数据。原请求不会因为文件后来打过补丁，就自动变成新密钥下的请求。

### 12.2 响应方向：构造可由公钥恢复的消息

当前工具构造以下响应对象：

```json
{
  "K": "请求中的原始序列号文本",
  "N": "注册姓名",
  "O": "注册组织",
  "T": 1700000000,
  "DI": "请求中的原始设备值",
  "FA": 0
}
```

这段排版只是为了展示字段，实际编码使用紧凑 UTF-8 JSON，不含排版空白。T 在窗口程序里取当前 Unix 秒数；文中固定的 1700000000 只用于算法测试。

M 在已还原解析器中是可选字符串字段，因此当前工具省略它；FA 固定为整数 0。工具对请求中的 K、DI 进行类型和长度检查，比原解析器的某些宽容分支更严格。

### 12.3 从 JSON 精确计算填充长度

令 JSON 的 UTF-8 字节数为 L。类型 1 块占用：

```text
1 字节 00
1 字节 01
PS 个 FF
1 字节 00
L 字节 JSON
```

总长固定 256 字节，所以：

```text
PS = 256 - L - 3
PS >= 8
L <= 245
```

构造完整块 R 后，计算：

```text
S = R^D mod N′
ActivationCode = Base64(S 的固定 256 字节大端表示)
```

最后立刻独立回验：

```text
R2 = S^e mod N′
要求 R2 的完整 256 字节与 R 完全相等
```

这一步能发现私有指数、整数端序、定长补零和块拼接方面的错误。回验通过后，客户端还要执行 JSON 与绑定检查，不能只比较前两个填充字节。

### 12.4 两个端序细节

文件中的 x64 立即数、Windows 的整数结构和 RSA 网络表示不是同一个层次。

- 读 PE 指令里的位移、指针时，按 x64 小端规则解释。
- RSA 的 256 字节输入和输出，按大端整数解释。
- C++ 多精度内部使用低位在前的 32 位 limb，进出算法时显式转换。

特别要保留 RSA 结果开头的零。把整数先转成最短字节串再直接 Base64，会得到不足 256 字节的输入，后面的长度或填充检查会失败。

### 12.5 一次完整的独立闭环

下面从零构造合成请求，使用新公钥加密，计算私有方向的解密，再生成响应、恢复 JSON、检查 K/DI，最后确认旧公钥不能恢复同样的消息。所需常量都在代码中，不读取任何中间结果。

P=`WIN` 是合成示例的演示字段，不代表已确认所有真实请求的该字段取值。示例设备值人为指定，不能替代实际设备请求。

\<!-- runnable:synthetic --\>

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
@'
import base64, json
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
PUBLIC_BASE64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I'
    'qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv'
    'a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF'
    'R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2'
    'WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt'
    'YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ'
    'awIDAQAB'
)

original = serialization.load_der_public_key(base64.b64decode(PUBLIC_BASE64)).public_numbers()
changed = PUBLIC_BASE64[:364]+'T'+PUBLIC_BASE64[365:]
public = serialization.load_der_public_key(base64.b64decode(changed)).public_numbers()
n,e = public.n,public.e
d = pow(e,-1,46*(n//47-1))
cipher = DES.new(bytes.fromhex('E97FB060774590AE'),DES.MODE_ECB).encrypt(
    bytes.fromhex('DBB782CE326520FF'))
serial = base64.b32encode(bytes.fromhex('682A')+cipher).decode('ascii')
assert serial == 'NAVC25AV5XXP7A5U'
fields = {'K':serial,'DI':'BLOG-SYNTHETIC-DEVICE','P':'WIN'}
request_json = json.dumps(fields,separators=(',',':')).encode('utf-8')
request_bytes = PKCS1_v1_5.new(RSA.construct((n,e))).encrypt(request_json)
request_code = base64.b64encode(request_bytes).decode('ascii')
opened = pow(int.from_bytes(request_bytes,'big'),d,n).to_bytes(256,'big')
separator = opened.find(b'\x00',2)
assert opened[:2] == b'\x00\x02' and separator >= 10
assert 0 not in opened[2:separator]
assert json.loads(opened[separator+1:].decode('utf-8')) == fields

response = {'K':fields['K'],'N':'Blog User','O':'Local Test',
            'T':1700000000,'DI':fields['DI'],'FA':0}
payload = json.dumps(response,ensure_ascii=False,separators=(',',':')).encode('utf-8')
assert len(payload) <= 245
em = b'\x00\x01'+b'\xff'*(253-len(payload))+b'\x00'+payload
signature = pow(int.from_bytes(em,'big'),d,n).to_bytes(256,'big')
recovered = pow(int.from_bytes(signature,'big'),e,n).to_bytes(256,'big')
assert recovered == em
split = recovered.find(b'\x00',2)
assert recovered[:2] == b'\x00\x01' and split >= 10
assert recovered[2:split] == b'\xff'*(split-2)
assert json.loads(recovered[split+1:].decode('utf-8')) == response
old_recovered = pow(int.from_bytes(signature,'big'),original.e,original.n).to_bytes(256,'big')
assert old_recovered != em
request_as_response = pow(int.from_bytes(request_bytes,'big'),e,n).to_bytes(256,'big')
assert request_as_response[:2] != b'\x00\x01'
response_code = base64.b64encode(signature).decode('ascii')
assert len(request_code) == len(response_code) == 344
print('serial:',serial)
print('request/response characters:',len(request_code),len(response_code))
print('request decrypt, type-1 response, JSON and K/DI: passed')
print('original key rejects this response: passed')
print('synthetic response:',response_code)
'@ | python -
```

请求的类型 2 填充含随机数，因此每次请求文本可以不同；固定响应字段和固定测试时间对应确定性的响应。检查重点是解密后的内容、固定 256 字节结构和绑定值都一致。

## 13. 将算法落到 C++：需要实现哪些层

原生工具由序列号、文本编码、固定宽度整数、请求与响应、文件事务和窗口事件组成。后面的代码把这些层放在同一个源文件中，只有 Windows SDK 与 C++ 标准库依赖。

### 13.1 公钥方向使用 Windows CNG

将 e=65537 表示为 `01 00 01`，连同 256 字节大端模数组装成 `BCRYPT_RSAPUBLIC_BLOB`。通过 `BCryptImportKeyPair` 导入后，以 `BCRYPT_PAD_NONE` 执行原始公钥运算。

这里需要恢复完整消息块，所以不直接改用 RSA-SHA256 验签接口。后者期待的哈希和 DigestInfo 结构与正文中的 JSON 消息不同。

### 13.2 私有方向使用 Montgomery 模幂

内部整数是 `std::array<std::uint32_t,64>`，共 2048 位，低位 limb 在前。进出算法时显式转换成 256 字节大端表示。乘法暂存使用 130 个 32 位元素，单步乘积和进位由 64 位整数承接。

选择 `R=2^2048`，定义：

```text
Mont(a,b) = a × b × R^(-1) mod N′
```

因为 N′ 为奇数，R 与 N′ 互素。先计算 R²，再转入 Montgomery 表示：

```text
result = Mont(1, R²)
base   = Mont(x, R²)

从最高位扫描指数：
    result = Mont(result,result)
    当前位为 1 时：result = Mont(result,base)

普通整数结果 = Mont(result,1)
```

完整代码中的 `Montgomery::Multiply` 实现乘积和归约，`Pow` 实现上述平方乘。输入不小于模数时直接拒绝，避免悄悄改变待验证数据。

### 13.3 字符串与 JSON 保留原始绑定

序列号归一化只用于确认用户有没有填错。写入响应时保留请求中的原始 K，DI 也逐字节保留。

JSON 采用紧凑 UTF-8；引号、反斜杠和控制字符必须转义。姓名长度按编码后的字节数检查，最多只能让完整 JSON 占 245 字节。解析器拒绝重复字段，并检查必需字段类型。

### 13.4 响应生成之后立即回验

生成流程不是“计算完 D 次幂就输出”：必须再用 CNG 的公钥运算恢复完整块，与构造时的 256 字节逐字节比较。这个独立方向可以发现模幂、端序和前导零的错误。

## 14. 文件补丁：可靠地修改一个字节，处理的事情不止一个字节

算法确认后，不能把工具写成“打开文件，在固定位置覆盖 54”就结束。用户可能选错目录、使用另一个版本、保留着历史备份，或者 Navicat 正占用 DLL。

### 14.1 用完整哈希定义两个可识别状态

| 状态   | libcc.dll SHA-256                                                  |
|--------|--------------------------------------------------------------------|
| 原版   | `d34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207` |
| 补丁版 | `bfae31129cfc21d84295f667a7efe85ad96d5575211664105b969b228ef192a1` |

文件状态是 `Missing / Unsupported / Original / Patched / Unknown`。只有 Original 启用补丁按钮，只有 Patched 启用恢复按钮。

匹配整个文件，既确认地址适用，也避免把已经被其他工具改过的文件当作原版。该工具因此只适用于本文指纹的版本，不提供猜测性适配。

### 14.2 原版备份不能被随便覆盖

备份文件名固定为：

```text
libcc.dll.keypatch18.original.bak
```

首次操作使用排他创建语义复制原文件，保存并验证备份。以后遇到同名备份时先检查其 SHA-256：原版备份可以继续用，不匹配的备份保留并停止操作。

这样重复点击补丁不会把补丁版再次复制为“原版备份”。

### 14.3 使用同目录临时文件和 ReplaceFileW

实际替换过程为：

```text
读取原 DLL，重新校验
  → 确认原版备份完整
  → 在内存中修改偏移 0x27EC415 的字节
  → 校验内存结果等于预期补丁哈希
  → 同目录排他创建随机临时文件
  → 写完整内容并 FlushFileBuffers
  → 再次检查当前 DLL 仍是预期输入
  → ReplaceFileW 替换目标
  → 校验替换后的完整哈希
```

同目录暂存便于使用系统文件替换语义。异常清理会先关闭暂存句柄，再删除临时文件，避免在句柄还禁止删除时留下残余。

`ReplaceFileW` 的正常替换还负责保留原文件的相关属性和访问控制信息；这并不意味着跨任意磁盘、断电或所有系统异常都具有额外事务保证。

完整实现放在后面的单文件程序里：`Patch`、`Restore` 负责状态和备份，`AtomicReplace` 负责暂存、刷新、重查和替换。

`NavicatRunning` 通过 Toolhelp32 枚举进程名，发现 `navicat.exe` 就提示先关闭；它不会强行结束用户进程。即使进程检查没有发现占用，文件被其他句柄锁住时，替换失败也会保留原文件和备份。

### 14.4 恢复为什么也要校验

恢复过程只接受已知补丁版 DLL 和通过校验的原版备份。任一项不匹配都停止。恢复后保留备份，允许读者自行核对。

恢复原版会撤销新公钥，因此先前根据新参数生成的响应不再匹配原公钥。文件恢复与产品保存的授权数据是两个层次，工具不伪装成恢复了所有注册表状态。

## 15. 原生窗口怎样组织

### 15.1 真正的 Win32 程序入口

主程序使用 `wWinMain`，注册 `WNDCLASSEXW`，调用 `CreateWindowExW` 创建窗口，控件直接采用系统 `EDIT`、`BUTTON`、`STATIC`。

界面主要分四块：

```text
安装目录 → 检查版本 / 应用补丁并备份 / 恢复原版
序列号   → 生成 / 复制，加姓名和组织
请求码   → 粘贴 / 检查请求 / 计算激活码
响应     → 只读文本框 / 复制激活码
```

目录选择使用 COM 的 `IFileOpenDialog` 和 `FOS_PICKFOLDERS`，剪贴板使用 `CF_UNICODETEXT`。界面文字统一使用宽字符，参与协议的数据显式转为 UTF-8。

### 15.2 为什么文件检查放到后台线程

一个 158 MB 左右的 DLL 做完整哈希和备份，会产生可感知的磁盘操作。全部塞进按钮事件里会让窗口暂时无法刷新。

`App::StartJob` 把目录和操作类型复制进 `std::thread`，工作线程只做文件操作，最后将结果通过 `PostMessageW(..., WM_APP+1, ...)` 交回 UI 线程。只有 UI 线程更新控件。

操作期间禁用目录编辑与相关按钮，关闭窗口也会被阻止，避免窗口销毁后后台工作还继续使用它。收到完成消息后回收结果对象、join 线程、更新文件状态并恢复按钮。

计算使用固定大小数据，不需要把 Navicat 加载进进程。工具也没有调用其内部导出、注入运行进程或执行网页教程提供的脚本。

### 15.3 旧响应必须随着输入失效

如果用户先计算出响应，又修改了姓名、组织、序列号或请求码，下方旧响应必须清除，复制按钮也要禁用。否则很容易把旧设备或旧序列号的响应复制回产品。

实现上监听 `WM_COMMAND / EN_CHANGE`；程序通过 `SetWindowTextW` 修改多行文本时，也显式调用清理函数。目录变化则清除文件状态，要求重新检查版本。

### 15.4 消息循环与键盘导航

窗口使用标准循环：

```cpp
MSG message{};
BOOL result;
while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
    if (!IsDialogMessageW(window, &message)) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}
```

`IsDialogMessageW` 负责 Tab 等控件导航。`GetMessageW` 的返回值要区分正数、0 和 −1；不能把 −1 也当作普通消息继续处理。

布局按系统 DPI 缩放。隐藏窗口测试既检查默认尺寸，也检查最小尺寸下所有控件是否在客户区内；这属于程序化布局验证，不能替代实际目视检查。

## 16. 完整单文件 C++ 原生窗口程序

将下面整段保存为 **`Keypatch.cpp`**。代码中已经包含密钥参数、序列号、JSON 解析、整数运算、文件补丁和原生窗口，编译时无需补充自定义头文件、清单文件或其他工程文件。

程序默认打开窗口，`--self-test` 参数则隐藏执行计算、输入失效、按钮状态、异步版本检查和窗口布局测试，以退出码报告结果，不写测试报告。

\<details\>
\<summary\>展开完整 C++17 / Win32 代码\</summary\>

\<!-- standalone-cpp --\>

```cpp
// Single-file C++17 / Win32 implementation.
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace serial {
using Block = std::array<unsigned char, 8>;
// Constant from the documented libcc.dll sample, RVA 0x8051568.
inline constexpr Block kKey{0xE9, 0x7F, 0xB0, 0x60, 0x77, 0x45, 0x90, 0xAE};
inline constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

inline void Check(NTSTATUS status, const char* operation) {
    if (status < 0) {
        throw std::runtime_error(std::string(operation) + " failed (NTSTATUS " +
                                 std::to_string(static_cast<unsigned long>(status)) + ")");
    }
}

inline Block Des(const Block& input, const Block& secret, bool encrypt) {
    struct Handles {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        ~Handles() {
            if (key) BCryptDestroyKey(key);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    } handles;
    Check(BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_DES_ALGORITHM,
                                     nullptr, 0), "Open DES provider");
    Check(BCryptSetProperty(handles.algorithm, BCRYPT_CHAINING_MODE,
                           reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                           sizeof(BCRYPT_CHAIN_MODE_ECB), 0), "Set ECB mode");
    auto mutableKey = secret;
    Check(BCryptGenerateSymmetricKey(handles.algorithm, &handles.key, nullptr, 0,
                                    mutableKey.data(), static_cast<ULONG>(mutableKey.size()), 0),
          "Create DES key");
    auto mutableInput = input;
    Block output{};
    ULONG length = 0;
    const auto transform = encrypt ? BCryptEncrypt : BCryptDecrypt;
    Check(transform(handles.key, mutableInput.data(), static_cast<ULONG>(mutableInput.size()),
                    nullptr, nullptr, 0, output.data(), static_cast<ULONG>(output.size()),
                    &length, 0), "Transform DES block");
    if (length != output.size()) throw std::runtime_error("Unexpected DES output length");
    return output;
}

inline std::string Encode(const std::array<unsigned char, 10>& bytes) {
    std::string text;
    std::uint32_t buffer = 0;
    unsigned bits = 0;
    for (auto byte : bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            text += kAlphabet[(buffer >> bits) & 31];
        }
    }
    return text;
}

inline std::array<unsigned char, 10> Decode(std::string_view text) {
    if (text.size() != 16) throw std::invalid_argument("Expected 16 characters");
    std::array<unsigned char, 10> bytes{};
    std::uint32_t buffer = 0;
    unsigned bits = 0;
    std::size_t index = 0;
    for (char ch : text) {
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        if (ch == '8') ch = 'I';
        if (ch == '9') ch = 'O';
        unsigned value;
        if (ch >= 'A' && ch <= 'Z') value = ch - 'A';
        else if (ch >= '2' && ch <= '7') value = ch - '2' + 26;
        else throw std::invalid_argument("Invalid Base32 character");
        buffer = (buffer << 5) | value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes[index++] = static_cast<unsigned char>(buffer >> bits);
        }
    }
    return bytes;
}

// Checks the exact field configuration used by this generator.
inline bool Validate(std::string_view text) {
    const auto bytes = Decode(text);
    if (bytes[0] != 0x68 || bytes[1] != 0x2A) return false;
    Block encrypted{};
    for (std::size_t i = 0; i < encrypted.size(); ++i) encrypted[i] = bytes[i + 2];
    const auto plain = Des(encrypted, kKey, false);
    return plain[3] == 0xCE && plain[4] == 0x32 && plain[5] == 0x65 &&
           plain[6] == 0x20 && plain[7] == 0xFF;
}

inline std::string GenerateFromPrefix(const std::array<unsigned char, 3>& prefix) {
    // P=3, table A; E=false, M=1; V=18; low nibble=0; Ctype=2.
    const Block plain{prefix[0], prefix[1], prefix[2], 0xCE, 0x32, 0x65, 0x20, 0xFF};
    const auto encrypted = Des(plain, kKey, true);
    std::array<unsigned char, 10> bytes{0x68, 0x2A};
    for (std::size_t i = 0; i < encrypted.size(); ++i) bytes[i + 2] = encrypted[i];
    return Encode(bytes);
}

inline std::string Generate(std::string_view previous = {}) {
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        std::array<unsigned char, 3> prefix{};
        Check(BCryptGenRandom(nullptr, prefix.data(), static_cast<ULONG>(prefix.size()),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG), "Generate random bytes");
        auto text = GenerateFromPrefix(prefix);
        if (text == previous) continue;
        if (!Validate(text)) throw std::runtime_error("Generated serial failed local checks");
        return text;
    }
    throw std::runtime_error("Unable to generate a different serial");
}

inline std::wstring Format(std::string_view text, bool separators = true) {
    std::wstring output;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (separators && i && i % 4 == 0) output += L'-';
        output += static_cast<wchar_t>(text[i]);
    }
    return output;
}
} // namespace serial

#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace activation {
using Bytes = std::vector<unsigned char>;
inline constexpr char kModulus[] =
    "c3576a1774a409a00098ccecf3cf48a9d5bd336748761de31bdc8f7262e7989886"
    "a4117813d54748c19ef283c0cb69090e674db7805c13282fb2c11f8229ef6b9b798"
    "e6df9d940280e8b142644d7190869016305e1f0660693b711e746eb6aceb2a301826"
    "49d032c4248f0512483854744206456d19d4d1fae3df87e256681888bb994809886e"
    "cf19c621cf769d680f8b54a6fb05722e1026d60d8cd9c653658f1faaef0a11a5d48"
    "44aaf132da8b89e96cbda8d48f2ae0382e8d9b299832f64d111de1b4512d2f5790"
    "6c2c937c39ad6324355ade0eb75da5c5fd3054847999c18ded70972511ce14749fd60"
    "cd759a6d14af9add67ae5eec5ba723c658eeb906b";

inline std::string Utf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("Invalid Unicode input.");
    std::string result(count, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        result.data(), count, nullptr, nullptr);
    return result;
}

inline std::wstring Wide(std::string_view text) {
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid UTF-8 data.");
    std::wstring result(count, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        result.data(), count);
    return result;
}

inline std::string LicenseValue(std::wstring_view text) {
    std::string value;
    for (wchar_t c : text) {
        if (c == L'-' || c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') continue;
        if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
        if (!((c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9')))
            throw std::invalid_argument("序列号只能包含英文字母或数字，可带连字符和空白。");
        value += static_cast<char>(c);
    }
    if (value.size() != 16) throw std::invalid_argument("去掉连字符和空白后，序列号应为 16 个字符。");
    return value;
}

struct Failure {
    std::string stage, applicationError;
    std::wstring detail;
};
[[noreturn]] inline void Fail(const char* stage, const wchar_t* detail, const char* code = "") {
    throw Failure{stage, code, detail};
}

inline Bytes Hex(std::string_view text) {
    if (text.size() % 2) throw std::runtime_error("Invalid hexadecimal key length.");
    Bytes result;
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return c-'0';
        if (c >= 'a' && c <= 'f') return c-'a'+10;
        if (c >= 'A' && c <= 'F') return c-'A'+10;
        throw std::runtime_error("Invalid hexadecimal key.");
    };
    for (std::size_t i = 0; i < text.size(); i += 2)
        result.push_back(static_cast<unsigned char>((digit(text[i]) << 4) | digit(text[i+1])));
    return result;
}

inline std::string Base64Encode(const Bytes& bytes) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        const unsigned a = bytes[i], b = i+1 < bytes.size() ? bytes[i+1] : 0,
                       c = i+2 < bytes.size() ? bytes[i+2] : 0;
        out += alphabet[a >> 2]; out += alphabet[((a & 3) << 4) | (b >> 4)];
        out += i+1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        out += i+2 < bytes.size() ? alphabet[c & 63] : '=';
    }
    return out;
}

inline Bytes Base64Decode(std::string_view text) {
    if (text.size() % 4) Fail("base64_strict", L"Base64 长度不是 4 的倍数。");
    auto digit = [](char c) -> unsigned {
        if (c >= 'A' && c <= 'Z') return c-'A';
        if (c >= 'a' && c <= 'z') return c-'a'+26;
        if (c >= '0' && c <= '9') return c-'0'+52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        Fail("base64_strict", L"包含无效的 Base64 字符。");
    };
    Bytes out;
    for (std::size_t i = 0; i < text.size(); i += 4) {
        const unsigned a = digit(text[i]), b = digit(text[i+1]);
        const bool p2 = text[i+2] == '=', p3 = text[i+3] == '=';
        if ((p2 && !p3) || ((p2 || p3) && i+4 != text.size()))
            Fail("base64_strict", L"Base64 的等号填充位置不正确。");
        const unsigned c = p2 ? 0 : digit(text[i+2]), d = p3 ? 0 : digit(text[i+3]);
        if ((p2 && (b & 15)) || (p3 && !p2 && (c & 3)))
            Fail("base64_strict", L"Base64 填充位不符合规范编码。");
        out.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
        if (!p2) out.push_back(static_cast<unsigned char>((b << 4) | (c >> 2)));
        if (!p3) out.push_back(static_cast<unsigned char>((c << 6) | d));
    }
    return out;
}

// CNG performs only the raw public RSA operation here; padding is checked below.
inline Bytes PublicRecover(const Bytes& input, std::string_view modulusHex = kModulus) {
    const auto modulus = Hex(modulusHex);
    if (modulus.size() != 256 || input.size() != 256)
        throw std::runtime_error("Expected a 2048-bit RSA key and a 256-byte block.");
    struct Handles {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        ~Handles() {
            if (key) BCryptDestroyKey(key);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    } handles;
    serial::Check(BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0), "Open RSA provider");
    BCRYPT_RSAKEY_BLOB header{BCRYPT_RSAPUBLIC_MAGIC, 2048, 3, 256, 0, 0};
    Bytes blob(sizeof(header));
    std::memcpy(blob.data(), &header, sizeof(header));
    blob.insert(blob.end(), {1, 0, 1});
    blob.insert(blob.end(), modulus.begin(), modulus.end());
    serial::Check(BCryptImportKeyPair(handles.algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB, &handles.key,
        blob.data(), static_cast<ULONG>(blob.size()), 0), "Import RSA public key");
    // Reduce once when the 256-byte integer is not smaller than the modulus.
    // This is sufficient for a 2048-bit modulus (n >= 2^2047) and a 256-byte S.
    auto block = input;
    if (!std::lexicographical_compare(block.begin(), block.end(), modulus.begin(), modulus.end())) {
        int borrow = 0;
        for (std::size_t i = block.size(); i-- > 0;) {
            const int value = static_cast<int>(block[i]) - modulus[i] - borrow;
            block[i] = static_cast<unsigned char>(value);
            borrow = value < 0 ? 1 : 0;
        }
    }
    Bytes out(256);
    ULONG length = 0;
    serial::Check(BCryptEncrypt(handles.key, block.data(), static_cast<ULONG>(block.size()),
        nullptr, nullptr, 0, out.data(), static_cast<ULONG>(out.size()), &length, BCRYPT_PAD_NONE), "RSA public recovery");
    if (length != 256) throw std::runtime_error("Unexpected RSA result length.");
    return out;
}

struct JsonValue {
    enum class Kind { Other, Object, String, Integer } kind = Kind::Other;
    std::string text;
    std::int64_t integer = 0;
};

// Bounded JSON parser for the recovered (at most 245-byte) message. Unknown
// values are parsed and discarded; duplicate object members are rejected.
class JsonParser {
    std::string_view input;
    std::size_t pos = 0;
    std::map<std::string, JsonValue> fields;
    void White() { while (pos < input.size() && (input[pos] == ' ' || input[pos] == '\t' || input[pos] == '\r' || input[pos] == '\n')) ++pos; }
    bool Eat(char c) { White(); if (pos < input.size() && input[pos] == c) { ++pos; return true; } return false; }
    [[noreturn]] void Bad() const { Fail("json_parse", L"恢复后的内容不是有效 JSON。", "90030001-1"); }
    static void AppendUtf8(std::string& out, unsigned code) {
        if (code < 0x80) out += static_cast<char>(code);
        else if (code < 0x800) {
            out += static_cast<char>(0xc0 | (code >> 6)); out += static_cast<char>(0x80 | (code & 63));
        } else if (code < 0x10000) {
            out += static_cast<char>(0xe0 | (code >> 12)); out += static_cast<char>(0x80 | ((code >> 6) & 63));
            out += static_cast<char>(0x80 | (code & 63));
        } else {
            out += static_cast<char>(0xf0 | (code >> 18)); out += static_cast<char>(0x80 | ((code >> 12) & 63));
            out += static_cast<char>(0x80 | ((code >> 6) & 63)); out += static_cast<char>(0x80 | (code & 63));
        }
    }
    unsigned Hex4() {
        unsigned code = 0;
        for (int i = 0; i < 4; ++i) {
            if (pos == input.size()) Bad();
            const char c = input[pos++];
            unsigned d;
            if (c >= '0' && c <= '9') d = c-'0';
            else if (c >= 'a' && c <= 'f') d = c-'a'+10;
            else if (c >= 'A' && c <= 'F') d = c-'A'+10;
            else Bad();
            code = (code << 4) | d;
        }
        return code;
    }
    std::string String() {
        if (!Eat('"')) Bad();
        std::string out;
        while (pos < input.size()) {
            const unsigned char c = static_cast<unsigned char>(input[pos++]);
            if (c == '"') return out;
            if (c < 0x20) Bad();
            if (c != '\\') { out += static_cast<char>(c); continue; }
            if (pos == input.size()) Bad();
            switch (input[pos++]) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                unsigned code = Hex4();
                if (code >= 0xd800 && code <= 0xdbff) {
                    if (pos+2 > input.size() || input.substr(pos, 2) != "\\u") Bad();
                    pos += 2;
                    const unsigned low = Hex4();
                    if (low < 0xdc00 || low > 0xdfff) Bad();
                    code = 0x10000 + ((code-0xd800) << 10) + low-0xdc00;
                } else if (code >= 0xdc00 && code <= 0xdfff) Bad();
                AppendUtf8(out, code); break;
            }
            default: Bad();
            }
        }
        Bad();
    }
    JsonValue Value(unsigned depth) {
        if (depth > 64) Bad();
        White();
        if (pos == input.size()) Bad();
        if (input[pos] == '"') return {JsonValue::Kind::String, String(), 0};
        if (Eat('{')) {
            std::set<std::string> names;
            if (!Eat('}')) {
                do {
                    auto key = String();
                    if (!names.insert(key).second) Fail("json_duplicate", L"数据包含重复的 JSON 字段。");
                    if (!Eat(':')) Bad();
                    auto value = Value(depth+1);
                    if (depth == 0) fields.emplace(std::move(key), std::move(value));
                    if (Eat('}')) return {JsonValue::Kind::Object, {}, 0};
                } while (Eat(','));
                Bad();
            }
            return {JsonValue::Kind::Object, {}, 0};
        }
        if (Eat('[')) {
            if (!Eat(']')) {
                do { Value(depth+1); if (Eat(']')) return {}; } while (Eat(','));
                Bad();
            }
            return {};
        }
        for (const std::string_view literal : {"true", "false", "null"}) {
            if (input.substr(pos, literal.size()) == literal) { pos += literal.size(); return {}; }
        }
        const auto start = pos;
        if (input[pos] == '-') ++pos;
        if (pos == input.size()) Bad();
        if (input[pos] == '0') ++pos;
        else {
            if (input[pos] < '1' || input[pos] > '9') Bad();
            while (pos < input.size() && input[pos] >= '0' && input[pos] <= '9') ++pos;
        }
        bool integer = true;
        if (pos < input.size() && input[pos] == '.') {
            integer = false; ++pos;
            const auto digits = pos;
            while (pos < input.size() && input[pos] >= '0' && input[pos] <= '9') ++pos;
            if (digits == pos) Bad();
        }
        if (pos < input.size() && (input[pos] == 'e' || input[pos] == 'E')) {
            integer = false; ++pos;
            if (pos < input.size() && (input[pos] == '+' || input[pos] == '-')) ++pos;
            const auto digits = pos;
            while (pos < input.size() && input[pos] >= '0' && input[pos] <= '9') ++pos;
            if (digits == pos) Bad();
        }
        std::int64_t number = 0;
        if (integer) {
            const auto result = std::from_chars(input.data()+start, input.data()+pos, number);
            if (result.ec == std::errc{} && result.ptr == input.data()+pos)
                return {JsonValue::Kind::Integer, {}, number};
        }
        return {};
    }
public:
    explicit JsonParser(std::string_view source) : input(source) {}
    std::pair<JsonValue, std::map<std::string, JsonValue>> Parse() {
        try { (void)Wide(input); } catch (const std::exception&) { Bad(); }
        auto root = Value(0);
        White();
        if (pos != input.size()) Bad();
        return {std::move(root), std::move(fields)};
    }
};

} // namespace activation

namespace keypatch {
inline constexpr char kPrivateExponent[] = "aed890f8e2d7740cdd55c73dbdd21f03217d78aa11230528525c673ffd034d06cc621187a974e2b4ab3db9d7af17eb3f54b41fede2f846074c486940159aa1e2ab8f909a341d7122aafd10a5ef10e006e71c8bc5f002cf7b4cca4b11f3236072c66ff878dd9350377a5ea639b9ba9d56b917c809fe46d7d5ff7e6b12e08a97e1b524790d5599f2740a53cd1f1fea92a4626552a1139effe671bccfcf86dfdacf0bf4863230e64bbc26caf6c04b53054b8718b9713ce5b2cf7baada412bc271e22a2d4cd80d6989312530f50713b95631145f566cd165731cf2e3242d0530501766220a88bc9bfb768218cb3f6f26181ed75f76b0d463910289206dc63dbe2701";
inline constexpr char kPatchedModulus[] = "c3576a1774a409a00098ccecf3cf48a9d5bd336748761de31bdc8f7262e7989886a4117813d54748c19ef283c0cb69090e674db7805c13282fb2c11f8229ef6b9b798e6df9d940280e8b142644d7190869016305e1f0660693b711e746eb6aceb2a30182649d032c4248f0512483854744206456d19d4d1fae3df87e256681888bb994809886ecf19c621cf769d680f8b54a6fb05722e1026d60d8cd9c653658f1faaef0a11a5d4844aaf132da8b89e96cbda8d48f2ae0382e8d9b299832f64d111de1b4512d2f57906c2c937c39ad6324355ade0eb75da5c5fd3054847999c18ded70972511ce14749fd60cd759a6d14ef9add67ae5eec5ba723c658eeb906b";
}

#include <array>

namespace rsa_math {
// Fixed-width integers for the pinned 2048-bit key. No runtime or external DLL.
using Integer = std::array<std::uint32_t, 64>;
inline Integer FromBytes(const activation::Bytes& bytes) {
    if (bytes.size() != 256) throw std::runtime_error("Expected a 256-byte RSA integer.");
    Integer value{};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        value[i / 4] |= std::uint32_t(bytes[255-i]) << ((i % 4) * 8);
    return value;
}
inline activation::Bytes ToBytes(const Integer& value) {
    activation::Bytes bytes(256);
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[255-i] = static_cast<unsigned char>(value[i / 4] >> ((i % 4) * 8));
    return bytes;
}
inline bool Less(const Integer& a, const Integer& b) {
    for (std::size_t i = a.size(); i-- > 0;)
        if (a[i] != b[i]) return a[i] < b[i];
    return false;
}
inline void Subtract(Integer& a, const Integer& b) {
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const std::uint64_t sub = std::uint64_t(b[i]) + borrow;
        const auto original = a[i];
        a[i] = static_cast<std::uint32_t>(std::uint64_t(original) - sub);
        borrow = std::uint64_t(original) < sub ? 1 : 0;
    }
}

class Montgomery {
    Integer modulus{}, rSquared{};
    std::uint32_t inverse = 0;
    void Double(Integer& x) const {
        std::uint32_t carry = 0;
        for (auto& limb : x) {
            const auto next = limb >> 31;
            limb = (limb << 1) | carry;
            carry = next;
        }
        if (carry || !Less(x, modulus)) Subtract(x, modulus);
    }
public:
    explicit Montgomery(const activation::Bytes& n) : modulus(FromBytes(n)) {
        if (!(modulus[0] & 1) || !(modulus.back() & 0x80000000))
            throw std::runtime_error("Expected an odd 2048-bit modulus.");
        std::uint32_t reciprocal = 1;
        for (unsigned i = 0; i < 5; ++i) reciprocal *= 2u - modulus[0] * reciprocal;
        inverse = 0u - reciprocal;
        rSquared[0] = 1;
        for (unsigned i = 0; i < 4096; ++i) Double(rSquared);
    }
    Integer Multiply(const Integer& a, const Integer& b) const {
        std::array<std::uint32_t, 130> t{};
        for (std::size_t i = 0; i < 64; ++i) {
            std::uint64_t carry = 0;
            for (std::size_t j = 0; j < 64; ++j) {
                const std::uint64_t sum = std::uint64_t(a[i]) * b[j] + t[i+j] + carry;
                t[i+j] = static_cast<std::uint32_t>(sum);
                carry = sum >> 32;
            }
            t[i+64] = static_cast<std::uint32_t>(carry);
        }
        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t multiplier = t[i] * inverse;
            std::uint64_t carry = 0;
            for (std::size_t j = 0; j < 64; ++j) {
                const std::uint64_t sum = std::uint64_t(multiplier) * modulus[j] + t[i+j] + carry;
                t[i+j] = static_cast<std::uint32_t>(sum);
                carry = sum >> 32;
            }
            std::size_t k = i+64;
            while (carry) {
                const std::uint64_t sum = std::uint64_t(t[k]) + carry;
                t[k++] = static_cast<std::uint32_t>(sum);
                carry = sum >> 32;
            }
        }
        Integer result{};
        std::copy_n(t.begin()+64, 64, result.begin());
        if (t[128] || !Less(result, modulus)) Subtract(result, modulus);
        return result;
    }
    activation::Bytes Pow(const activation::Bytes& bytes, const activation::Bytes& exponent) const {
        const auto input = FromBytes(bytes);
        if (!Less(input, modulus)) throw std::invalid_argument("输入块与当前密钥不匹配。");
        Integer one{}; one[0] = 1;
        auto result = Multiply(one, rSquared);
        const auto base = Multiply(input, rSquared);
        for (unsigned char byte : exponent) {
            for (int bit = 7; bit >= 0; --bit) {
                result = Multiply(result, result);
                if ((byte >> bit) & 1) result = Multiply(result, base);
            }
        }
        return ToBytes(Multiply(result, one));
    }
};
} // namespace rsa_math

#include <filesystem>
#include <fstream>
#include <chrono>
#include <tlhelp32.h>

namespace keypatch {
namespace fs = std::filesystem;
using activation::Bytes;
using Fields = std::map<std::string, activation::JsonValue>;
inline constexpr wchar_t kBackup[] = L"libcc.dll.keypatch18.original.bak";
inline constexpr char kOriginalHash[] = "d34a8194da9f5a5459ab25a9323df7ec787cdddc90ad58b33bc62d0ca84a7207";
inline constexpr char kPatchedHash[] = "bfae31129cfc21d84295f667a7efe85ad96d5575211664105b969b228ef192a1";
inline constexpr std::size_t kPatchOffset = 0x27EC415;

[[noreturn]] inline void Fail(const char* message) { throw std::runtime_error(message); }
inline void WinCheck(BOOL value, const char* message) {
    if (!value) throw std::runtime_error(std::string(message) + " (Windows " + std::to_string(GetLastError()) + ")");
}
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
    void Close() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); value = INVALID_HANDLE_VALUE; }
};
inline std::string HexString(const unsigned char* bytes, std::size_t size) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < size; ++i) { result += alphabet[bytes[i] >> 4]; result += alphabet[bytes[i] & 15]; }
    return result;
}
class Sha256 {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
public:
    Sha256() {
        serial::Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0), "Open SHA256");
        const auto status = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr; serial::Check(status, "Create SHA256"); }
    }
    ~Sha256() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void Add(const unsigned char* data, std::size_t size) {
        while (size) {
            const auto count = static_cast<ULONG>(std::min<std::size_t>(size, 1024*1024));
            serial::Check(BCryptHashData(hash, const_cast<PUCHAR>(data), count, 0), "SHA256 input");
            data += count; size -= count;
        }
    }
    std::string Finish() {
        std::array<unsigned char, 32> result{};
        serial::Check(BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0), "Finish SHA256");
        return HexString(result.data(), result.size());
    }
};
inline std::string Digest(const Bytes& data) { Sha256 hash; hash.Add(data.data(), data.size()); return hash.Finish(); }
inline std::string Digest(const fs::path& file) {
    Handle input(CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    WinCheck(input.value != INVALID_HANDLE_VALUE, "无法读取文件，请检查目录及权限");
    Sha256 hash;
    std::array<unsigned char, 65536> buffer{};
    DWORD count = 0;
    do {
        WinCheck(ReadFile(input.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr), "读取文件失败");
        hash.Add(buffer.data(), count);
    } while (count);
    return hash.Finish();
}
inline Bytes ReadBytes(const fs::path& file) {
    std::ifstream stream(file, std::ios::binary | std::ios::ate);
    if (!stream) Fail("无法读取文件。");
    const auto length = stream.tellg();
    if (length < 0 || length > 200*1024*1024) Fail("文件大小超出支持范围。");
    Bytes result(static_cast<std::size_t>(length));
    stream.seekg(0);
    if (!result.empty() && !stream.read(reinterpret_cast<char*>(result.data()), length)) Fail("文件读取不完整。");
    return result;
}
enum class State { Unknown, Missing, Unsupported, Original, Patched };
inline State InstallationState(const fs::path& directory) {
    const auto file = directory / L"libcc.dll";
    if (!fs::is_regular_file(file)) return State::Missing;
    const auto hash = Digest(file);
    if (hash == kOriginalHash) return State::Original;
    if (hash == kPatchedHash) return State::Patched;
    return State::Unsupported;
}
inline bool NavicatRunning() {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    WinCheck(snapshot.value != INVALID_HANDLE_VALUE, "无法检查运行中的程序");
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    BOOL more = Process32FirstW(snapshot.value, &entry);
    while (more) {
        if (_wcsicmp(entry.szExeFile, L"navicat.exe") == 0) return true;
        more = Process32NextW(snapshot.value, &entry);
    }
    if (GetLastError() != ERROR_NO_MORE_FILES) Fail("无法完整检查运行中的程序。");
    return false;
}
inline void AtomicReplace(const fs::path& target, const Bytes& bytes, const char* expected) {
    std::array<unsigned char, 12> random{};
    serial::Check(BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG), "Generate temporary name");
    const fs::path temporary = target.parent_path() / (L".keypatch18-" + activation::Wide(HexString(random.data(), random.size())) + L".tmp");
    Handle output(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    WinCheck(output.value != INVALID_HANDLE_VALUE, "无法创建临时文件，请检查目录写入权限");
    struct Cleanup {
        fs::path path; Handle& output;
        ~Cleanup() { output.Close(); std::error_code ignored; fs::remove(path, ignored); }
    } cleanup{temporary, output};
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        DWORD written = 0;
        const auto count = static_cast<DWORD>(std::min<std::size_t>(bytes.size()-offset, 1024*1024));
        WinCheck(WriteFile(output.value, bytes.data()+offset, count, &written, nullptr), "写入临时文件失败");
        if (!written) Fail("临时文件写入不完整。");
        offset += written;
    }
    WinCheck(FlushFileBuffers(output.value), "保存临时文件失败");
    output.Close();
    if (Digest(target) != expected) Fail("操作期间文件已变化，请重新检查目录。");
    WinCheck(ReplaceFileW(target.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr), "替换文件失败，请关闭 Navicat 并检查写入权限");
}
inline std::wstring Patch(const fs::path& directory, bool checkProcess = true) {
    const auto state = InstallationState(directory);
    if (state == State::Patched) return L"已经应用此版本补丁。";
    if (state != State::Original) Fail("文件与支持的 Premium 18.0.6 版本不匹配，未修改。");
    if (checkProcess && NavicatRunning()) Fail("请先关闭 Navicat，再应用补丁。");
    const auto target = fs::absolute(directory) / L"libcc.dll";
    const auto backup = target.parent_path() / kBackup;
    auto bytes = ReadBytes(target);
    if (Digest(bytes) != kOriginalHash || bytes.size() <= kPatchOffset || bytes[kPatchOffset] != 0x53) Fail("原文件校验失败。");
    if (!fs::exists(backup)) {
        WinCheck(CopyFileW(target.c_str(), backup.c_str(), TRUE), "无法创建原版备份");
        Handle saved(CreateFileW(backup.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        WinCheck(saved.value != INVALID_HANDLE_VALUE, "无法确认备份已保存");
        WinCheck(FlushFileBuffers(saved.value), "无法保存原版备份");
    }
    if (Digest(backup) != kOriginalHash) Fail("已有备份不匹配，已保留该备份并停止操作。");
    bytes[kPatchOffset] = 0x54;
    if (Digest(bytes) != kPatchedHash) Fail("补丁结果校验失败。");
    AtomicReplace(target, bytes, kOriginalHash);
    if (Digest(target) != kPatchedHash) Fail("替换后的文件校验失败，请使用备份恢复。");
    return L"补丁已应用，原版已备份。请重启 Navicat，再取得新的请求码。";
}
inline std::wstring Restore(const fs::path& directory, bool checkProcess = true) {
    const auto state = InstallationState(directory);
    if (state == State::Original) return L"当前已经是原版文件。";
    if (state != State::Patched) Fail("当前文件不是本工具生成的补丁版本，未修改。");
    if (checkProcess && NavicatRunning()) Fail("请先关闭 Navicat，再恢复原版。");
    const auto target = fs::absolute(directory) / L"libcc.dll";
    auto bytes = ReadBytes(target.parent_path() / kBackup);
    if (Digest(bytes) != kOriginalHash) Fail("原版备份校验失败，未修改。");
    AtomicReplace(target, bytes, kPatchedHash);
    if (Digest(target) != kOriginalHash) Fail("恢复后的文件校验失败。");
    return L"已恢复原版文件，备份继续保留。";
}
inline std::string Normalize(std::wstring_view text) {
    auto value = activation::LicenseValue(text);
    for (auto& c : value) { if (c == '8') c = 'I'; if (c == '9') c = 'O'; }
    (void)serial::Decode(value);
    return value;
}
inline const rsa_math::Montgomery& Math() {
    static const rsa_math::Montgomery math(activation::Hex(kPatchedModulus)); return math;
}
inline Bytes Private(const Bytes& value) { return Math().Pow(value, activation::Hex(kPrivateExponent)); }
inline Bytes DecodeCode(std::wstring_view text) {
    if (text.size() > 16384) Fail("输入过长，请只粘贴请求码或激活码。");
    std::string clean;
    for (wchar_t ch : text) {
        if (ch == L' ' || ch == L'\r' || ch == L'\n' || ch == L'\t' || ch == L'\v' || ch == L'\f') continue;
        if (ch > 127) Fail("输入应为 Base64 文本。");
        clean += static_cast<char>(ch);
    }
    if (clean.size() != 344) Fail("请复制完整的请求码或激活码，应为 344 个 Base64 字符。");
    const auto block = activation::Base64Decode(clean);
    if (block.size() != 256 || activation::Base64Encode(block) != clean) Fail("Base64 编码不完整或不规范。");
    if (!rsa_math::Less(rsa_math::FromBytes(block), rsa_math::FromBytes(activation::Hex(kPatchedModulus)))) Fail("输入块与当前密钥不匹配。");
    return block;
}
inline Fields ParsePayload(const Bytes& block, unsigned char type) {
    const auto separator = std::find(block.begin()+2, block.end(), 0);
    if (block[0] != 0 || block[1] != type || separator-block.begin() < 10 || separator == block.end())
        Fail("请求或签名不匹配。请应用补丁并重启 Navicat，再取得新的请求码。");
    if (type == 1 && !std::all_of(block.begin()+2, separator, [](unsigned char b) { return b == 255; })) Fail("激活码填充不正确。");
    const std::string payload(separator+1, block.end());
    auto parsed = activation::JsonParser(payload).Parse();
    if (parsed.first.kind != activation::JsonValue::Kind::Object) Fail("请求数据必须是 JSON 对象。");
    return std::move(parsed.second);
}
inline const std::string& StringField(const Fields& fields, const char* name) {
    const auto it = fields.find(name);
    if (it == fields.end() || it->second.kind != activation::JsonValue::Kind::String) Fail("请求字段缺失或类型不正确。");
    return it->second.text;
}
inline Fields DecryptRequest(std::wstring_view text) {
    auto fields = ParsePayload(Private(DecodeCode(text)), 2);
    const auto& serialValue = StringField(fields, "K");
    const auto& device = StringField(fields, "DI");
    if (device.empty() || device.size() > 80) Fail("设备标识为空或过长。");
    if (!serial::Validate(Normalize(activation::Wide(serialValue)))) Fail("请求序列号不符合 Premium 18 配置。");
    return fields;
}
inline std::string Quote(std::string_view value) {
    (void)activation::Wide(value);
    std::string result = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c == '\b') result += "\\b";
        else if (c == '\f') result += "\\f";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else if (c < 0x20) result += "\\u00" + HexString(&c, 1);
        else result += static_cast<char>(c);
    }
    return result + '"';
}
inline Fields RecoverResponse(std::wstring_view text) {
    return ParsePayload(activation::PublicRecover(DecodeCode(text), kPatchedModulus), 1);
}
inline std::string GenerateResponse(std::wstring_view request, std::wstring_view name, std::wstring_view organization,
    std::wstring_view expectedSerial, std::int64_t timestamp = -1) {
    const auto fields = DecryptRequest(request);
    const auto& serialValue = StringField(fields, "K");
    if (Normalize(activation::Wide(serialValue)) != Normalize(expectedSerial)) Fail("请求码中的序列号与上方不同，请使用同一序列号生成请求。");
    if (timestamp == -1) timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const auto user = activation::Utf8(name), org = activation::Utf8(organization);
    const auto& device = StringField(fields, "DI");
    const std::string payload = "{\"K\":" + Quote(serialValue) + ",\"N\":" + Quote(user) + ",\"O\":" + Quote(org) +
        ",\"T\":" + std::to_string(timestamp) + ",\"DI\":" + Quote(device) + ",\"FA\":0}";
    if (payload.size() > 245) Fail("姓名或组织名称过长，请缩短后重试。");
    Bytes encoded(256, 255);
    encoded[0] = 0; encoded[1] = 1; encoded[255-payload.size()] = 0;
    std::copy(payload.begin(), payload.end(), encoded.end()-payload.size());
    const auto signature = Private(encoded);
    if (activation::PublicRecover(signature, kPatchedModulus) != encoded) Fail("生成结果未通过公钥回验。");
    return activation::Base64Encode(signature);
}
inline std::wstring ErrorText() {
    try { throw; }
    catch (const activation::Failure& error) { return error.detail; }
    catch (const std::exception& error) {
        try { return activation::Wide(error.what()); }
        catch (...) {
            const int count = MultiByteToWideChar(CP_ACP, 0, error.what(), -1, nullptr, 0);
            std::wstring result(count > 0 ? count : 1, L'\0');
            if (count > 0) MultiByteToWideChar(CP_ACP, 0, error.what(), -1, result.data(), count);
            if (!result.empty() && result.back() == L'\0') result.pop_back();
            return result.empty() ? L"文件操作失败，请检查路径和权限。" : result;
        }
    }
    catch (...) { return L"操作无法完成。"; }
}
} // namespace keypatch

#include <commctrl.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <memory>
#include <thread>

namespace {
constexpr int PathBox=101, Browse=102, Check=103, Patch=104, Restore=105;
constexpr int Serial=106, Generate=107, CopySerial=108, Name=109, Organization=110;
constexpr int Request=111, PasteRequest=112, Inspect=113, Calculate=114, Response=115, CopyResponse=116;
constexpr UINT JobComplete = WM_APP+1;
constexpr wchar_t ClassName[] = L"NavicatKeypatch18NativeCpp";
using keypatch::fs::path;

std::wstring ReadText(HWND window) {
    const int length = GetWindowTextLengthW(window);
    std::wstring text(static_cast<std::size_t>(length)+1, L'\0');
    text.resize(GetWindowTextW(window, text.data(), length+1));
    return text;
}
path ExecutablePath() {
    std::wstring buffer(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!length || length == buffer.size()) keypatch::Fail("无法取得程序路径。");
    buffer.resize(length); return path(buffer);
}
path DefaultDirectory() {
    auto parent = ExecutablePath().parent_path();
    while (!parent.empty()) {
        if (keypatch::fs::is_regular_file(parent/L"navicat.exe") && keypatch::fs::is_regular_file(parent/L"libcc.dll")) return parent;
        const auto next = parent.parent_path(); if (next == parent) break; parent = next;
    }
    return keypatch::fs::current_path();
}
struct JobResult { keypatch::State state = keypatch::State::Unknown; std::wstring message, error; };
struct App {
    HWND window = nullptr;
    std::map<int, HWND> controls;
    HFONT normal=nullptr, heading=nullptr, code=nullptr, serialFont=nullptr;
    HBRUSH background=nullptr;
    int dpi=96, errorCount=0;
    bool ready=false, busy=false, testing=false;
    keypatch::State state=keypatch::State::Unknown;
    std::thread worker;
    ~App() {
        if (worker.joinable()) worker.join();
        for (auto resource : {normal, heading, code, serialFont}) if (resource) DeleteObject(resource);
        if (background) DeleteObject(background);
    }
    int Scale(int n) const { return MulDiv(n, dpi, 96); }
    HWND Get(int id) const { return controls.at(id); }
    std::wstring Text(int id) const { return ReadText(Get(id)); }
    void Set(int id, const std::wstring& text) {
        SetWindowTextW(Get(id), text.c_str());
        if (!ready) return;
        if (id==Serial || id==Name || id==Organization || id==Request) ClearResponse();
        else if (id==PathBox) DirectoryChanged();
    }
    void Status(const std::wstring& text) { Set(210, text); }
    void Error(const std::wstring& text) {
        ++errorCount; Status(text);
        if (!testing) MessageBoxW(window, text.c_str(), L"操作未完成", MB_OK|MB_ICONERROR);
    }
    void ClearResponse() {
        if (!Text(Response).empty()) {
            Set(Response, L""); Status(L"输入已变化，请重新计算激活码。"); SyncButtons();
        }
    }
    void DirectoryChanged() {
        state=keypatch::State::Unknown; Set(204, L"目录已变化，请重新检查版本。"); SyncButtons();
    }
    void SyncButtons() {
        for (int id : {Browse, Check, Patch, Restore, Generate, CopySerial, PasteRequest, Inspect, Calculate, CopyResponse})
            EnableWindow(Get(id), !busy);
        EnableWindow(Get(PathBox), !busy);
        if (!busy) {
            EnableWindow(Get(Patch), state==keypatch::State::Original);
            EnableWindow(Get(Restore), state==keypatch::State::Patched);
            EnableWindow(Get(CopyResponse), !Text(Response).empty());
        }
    }
    HWND Control(int id, const wchar_t* kind, const wchar_t* text, DWORD style=0, HFONT font=nullptr) {
        const bool edit = wcscmp(kind, L"EDIT")==0;
        auto child=CreateWindowExW(edit ? WS_EX_CLIENTEDGE : 0, kind, text, WS_CHILD|WS_VISIBLE|style,
            0,0,10,10,window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
        keypatch::WinCheck(child!=nullptr, "无法创建窗口控件");
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(font ? font : normal), TRUE);
        if (edit) SendMessageW(child, EM_SETLIMITTEXT, 16384, 0);
        controls.emplace(id, child); return child;
    }
    void Button(int id, const wchar_t* text) { Control(id,L"BUTTON",text,WS_TABSTOP|BS_PUSHBUTTON); }
    void CreateControls() {
        HDC dc=GetDC(window); dpi=GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(window,dc);
        auto font=[&](const wchar_t* face,int size,int weight=FW_NORMAL) {
            return CreateFontW(-Scale(size),0,0,0,weight,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,face);
        };
        normal=font(L"Microsoft YaHei UI",16); heading=font(L"Microsoft YaHei UI",28,FW_BOLD);
        code=font(L"Consolas",17); serialFont=font(L"Consolas",21);
        background=CreateSolidBrush(RGB(246,248,251));
        auto label=[&](int id,const wchar_t* text,HFONT f=nullptr) { Control(id,L"STATIC",text,0,f); };
        label(201,L"Navicat Keypatch",heading);
        label(202,L"Premium 18.0.6 · Windows x64 · C++ 原生程序");
        label(203,L"1  安装目录");
        Control(PathBox,L"EDIT",DefaultDirectory().c_str(),WS_TABSTOP|ES_AUTOHSCROLL);
        Button(Browse,L"选择目录"); label(204,L"选择安装目录后检查版本。");
        Button(Check,L"检查版本"); Button(Patch,L"应用补丁并备份"); Button(Restore,L"恢复原版");
        label(205,L"2  序列号与注册信息");
        Control(Serial,L"EDIT",serial::Format(serial::Generate()).c_str(),WS_TABSTOP|ES_AUTOHSCROLL,serialFont);
        Button(Generate,L"生成序列号"); Button(CopySerial,L"复制序列号");
        label(206,L"注册姓名"); Control(Name,L"EDIT",L"User",WS_TABSTOP|ES_AUTOHSCROLL);
        label(207,L"注册组织"); Control(Organization,L"EDIT",L"Personal",WS_TABSTOP|ES_AUTOHSCROLL);
        label(208,L"3  请求码（应用补丁并重启后，从 Navicat 复制）");
        const DWORD multi=WS_TABSTOP|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|ES_WANTRETURN;
        Control(Request,L"EDIT",L"",multi,code); Button(PasteRequest,L"粘贴请求码");
        Button(Inspect,L"检查请求"); Button(Calculate,L"计算激活码");
        label(209,L"4  激活码（复制回 Navicat 手动激活窗口）");
        Control(Response,L"EDIT",L"",multi|ES_READONLY,code); Button(CopyResponse,L"复制激活码");
        label(210,L"先应用补丁，再使用重新生成的请求码。");
        ready=true; Layout(); SyncButtons();
    }
    void Layout() {
        if (!ready) return;
        RECT r{}; GetClientRect(window,&r);
        const int width=MulDiv(r.right,96,dpi),height=MulDiv(r.bottom,96,dpi),margin=26,available=width-52;
        auto place=[&](int id,int x,int y,int w,int h) { MoveWindow(Get(id),Scale(x),Scale(y),Scale(w),Scale(h),TRUE); };
        auto row=[&](int id,int y,int h) { place(id,margin,y,available,h); };
        row(201,15,36); row(202,53,25); row(203,88,24);
        place(PathBox,margin,116,available-110,31); place(Browse,width-margin-100,116,100,31);
        row(204,154,25); place(Check,margin,184,110,33); place(Patch,margin+120,184,172,33); place(Restore,margin+302,184,110,33);
        row(205,236,24); place(Serial,margin,265,available-302,37);
        place(Generate,width-margin-292,265,140,37); place(CopySerial,width-margin-142,265,142,37);
        place(206,margin,317,76,28); const int first=(available-186)/2;
        place(Name,margin+80,313,first,31); place(207,margin+first+100,317,76,28);
        place(Organization,margin+first+180,313,available-first-180,31);
        row(208,363,25);
        const int requestHeight=std::max(65,105+(height-800)/2);
        row(Request,394,requestHeight); const int actionsY=394+requestHeight+9;
        place(PasteRequest,margin,actionsY,128,34); place(Inspect,margin+138,actionsY,112,34); place(Calculate,margin+260,actionsY,148,34);
        const int labelY=actionsY+48,responseY=labelY+31,responseHeight=std::max(65,height-responseY-92);
        row(209,labelY,25); row(Response,responseY,responseHeight);
        const int footerY=responseY+responseHeight+12;
        place(210,margin,footerY+1,available-172,64); place(CopyResponse,width-margin-156,footerY,156,35);
        InvalidateRect(window,nullptr,TRUE);
    }
    void StartJob(int operation) {
        if (busy) return;
        const path directory=Text(PathBox);
        busy=true; SyncButtons();
        Set(204,L"正在核对文件…");
        if (operation==Patch) Status(L"正在备份并应用补丁…");
        if (operation==Restore) Status(L"正在恢复原版…");
        try { worker=std::thread([this,directory,operation] {
            auto result=std::make_unique<JobResult>();
            try {
                if (operation==Patch) result->message=keypatch::Patch(directory);
                if (operation==Restore) result->message=keypatch::Restore(directory);
                result->state=keypatch::InstallationState(directory);
            } catch (...) { result->error=keypatch::ErrorText(); }
            if (PostMessageW(window,JobComplete,0,reinterpret_cast<LPARAM>(result.get()))) result.release();
        }); } catch (...) { busy=false; SyncButtons(); throw; }
    }
    void CompleteJob(JobResult* pointer) {
        std::unique_ptr<JobResult> result(pointer);
        if (worker.joinable()) worker.join();
        busy=false; state=result->state;
        if (!result->error.empty()) { Set(204,L"操作未完成，请处理提示后重新检查版本。"); Error(result->error); }
        else {
            const wchar_t* description=L"目录已变化，请重新检查版本。";
            switch (state) {
            case keypatch::State::Original: description=L"版本匹配 · 原版文件，可应用补丁"; break;
            case keypatch::State::Patched: description=L"版本匹配 · 已应用补丁，可生成新请求"; break;
            case keypatch::State::Missing: description=L"未找到 libcc.dll，请选择 Navicat 安装目录"; break;
            case keypatch::State::Unsupported: description=L"文件不匹配：仅支持已核对的 Premium 18.0.6 版本"; break;
            default: break;
            }
            Set(204,description); if (!result->message.empty()) Status(result->message);
        }
        SyncButtons();
    }
    void SelectDirectory() {
        IFileOpenDialog* dialog=nullptr;
        const auto created=CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog));
        if (FAILED(created)) keypatch::Fail("无法打开目录选择窗口。");
        struct Scope { IFileOpenDialog* p; ~Scope() { p->Release(); } } scope{dialog};
        DWORD options=0; dialog->GetOptions(&options);
        dialog->SetOptions(options|FOS_PICKFOLDERS|FOS_FORCEFILESYSTEM); dialog->SetTitle(L"选择 Navicat 安装目录");
        const auto shown=dialog->Show(window);
        if (shown==HRESULT_FROM_WIN32(ERROR_CANCELLED)) return;
        if (FAILED(shown)) keypatch::Fail("目录选择失败。");
        IShellItem* item=nullptr;
        if (FAILED(dialog->GetResult(&item))) keypatch::Fail("无法读取所选目录。");
        struct ItemScope { IShellItem* p; ~ItemScope() { p->Release(); } } itemScope{item};
        PWSTR selected=nullptr;
        if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH,&selected))) keypatch::Fail("无法读取所选目录路径。");
        std::wstring value(selected); CoTaskMemFree(selected); Set(PathBox,value); StartJob(Check);
    }
    void Copy(const std::wstring& text) {
        if (!OpenClipboard(window)) keypatch::Fail("剪贴板忙，请重试。");
        struct Scope { ~Scope() { CloseClipboard(); } } scope;
        const auto size=(text.size()+1)*sizeof(wchar_t);
        HGLOBAL block=GlobalAlloc(GMEM_MOVEABLE,size);
        if (!block) keypatch::Fail("无法分配剪贴板内存。");
        void* memory=GlobalLock(block);
        if (!memory) { GlobalFree(block); keypatch::Fail("无法写入剪贴板。"); }
        std::memcpy(memory,text.c_str(),size); GlobalUnlock(block);
        if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT,block)) { GlobalFree(block); keypatch::Fail("无法写入剪贴板。"); }
    }
    void Paste() {
        if (!OpenClipboard(window)) keypatch::Fail("剪贴板忙，请重试。");
        struct Scope { ~Scope() { CloseClipboard(); } } scope;
        const auto block=GetClipboardData(CF_UNICODETEXT);
        if (!block) keypatch::Fail("剪贴板中没有文本。");
        const auto data=static_cast<const wchar_t*>(GlobalLock(block));
        if (!data) keypatch::Fail("无法读取剪贴板。");
        struct Lock { HANDLE h; ~Lock() { GlobalUnlock(h); } } lock{block};
        const auto capacity=std::min<std::size_t>(GlobalSize(block)/sizeof(wchar_t),16385);
        std::size_t count=0; while (count<capacity && data[count]) ++count;
        if (count==capacity) keypatch::Fail("剪贴板文本过长或不完整。");
        Set(Request,std::wstring(data,count));
    }
    void Dispatch(int id) {
        if (busy) return;
        switch (id) {
        case Browse: SelectDirectory(); break;
        case Check: case Patch: case Restore: StartJob(id); break;
        case Generate: Set(Serial,serial::Format(serial::Generate())); Status(L"已生成当前 Premium 18 配置的序列号。"); break;
        case CopySerial: Copy(serial::Format(keypatch::Normalize(Text(Serial)))); Status(L"已复制序列号。"); break;
        case PasteRequest: Paste(); break;
        case Inspect: {
            const auto fields=keypatch::DecryptRequest(Text(Request));
            if (keypatch::Normalize(activation::Wide(keypatch::StringField(fields,"K")))!=keypatch::Normalize(Text(Serial)))
                keypatch::Fail("请求中的序列号与上方不同。");
            Status(L"请求已解密，序列号一致，设备标识完整。可以计算激活码。"); break;
        }
        case Calculate: {
            Set(Response,L""); SyncButtons();
            const auto value=keypatch::GenerateResponse(Text(Request),Text(Name),Text(Organization),Text(Serial));
            Set(Response,activation::Wide(value)); SyncButtons();
            Status(L"激活码已生成并通过公钥回验，请复制回对应的手动激活窗口。"); break;
        }
        case CopyResponse:
            if (Text(Response).empty()) keypatch::Fail("请先计算激活码。");
            Copy(Text(Response)); Status(L"已复制激活码。"); break;
        default: break;
        }
    }
};

LRESULT CALLBACK WindowProc(HWND window,UINT message,WPARAM w,LPARAM l) {
    auto app=reinterpret_cast<App*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if (message==WM_NCCREATE) {
        app=static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);
        app->window=window; SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(app));
    }
    if (!app) return DefWindowProcW(window,message,w,l);
    try {
        switch (message) {
        case WM_CREATE: app->CreateControls(); return 0;
        case WM_SIZE: app->Layout(); return 0;
        case WM_GETMINMAXINFO: {
            auto info=reinterpret_cast<MINMAXINFO*>(l);
            info->ptMinTrackSize={app->Scale(850),app->Scale(760)}; return 0;
        }
        case WM_COMMAND:
            if (app->ready) {
                const int id=LOWORD(w),notification=HIWORD(w);
                if (notification==EN_CHANGE && (id==Serial || id==Name || id==Organization || id==Request)) app->ClearResponse();
                else if (notification==EN_CHANGE && id==PathBox) app->DirectoryChanged();
                else if (notification==BN_CLICKED) app->Dispatch(id);
            }
            return 0;
        case JobComplete: app->CompleteJob(reinterpret_cast<JobResult*>(l)); return 0;
        case WM_CTLCOLORSTATIC:
            SetBkMode(reinterpret_cast<HDC>(w),TRANSPARENT); SetTextColor(reinterpret_cast<HDC>(w),RGB(38,54,76));
            return reinterpret_cast<LRESULT>(app->background);
        case WM_ERASEBKGND: {
            RECT client{}; GetClientRect(window,&client); FillRect(reinterpret_cast<HDC>(w),&client,app->background); return 1;
        }
        case WM_CLOSE:
            if (app->busy) app->Status(L"文件操作进行中，请完成后再关闭窗口。"); else DestroyWindow(window);
            return 0;
        case WM_DESTROY: PostQuitMessage(0); return 0;
        default: break;
        }
    } catch (...) {
        const auto error=keypatch::ErrorText();
        if (message==WM_CREATE) { if (!app->testing) MessageBoxW(window,error.c_str(),L"启动失败",MB_OK|MB_ICONERROR); return -1; }
        app->Error(error);
    }
    return DefWindowProcW(window,message,w,l);
}
void Require(bool value,const char* message) { if (!value) throw std::runtime_error(message); }
void RunGuiChecks(App& app) {
    const wchar_t* testSerial=L"NAVC25AV5XXP7A5U";
    const char* testDevice="LOCAL-CPP-TEST-0";
    const std::string payload="{\"K\":\"NAVC25AV5XXP7A5U\",\"DI\":\"LOCAL-CPP-TEST-0\",\"P\":\"WIN\"}";
    keypatch::Bytes block(256,255); block[0]=0; block[1]=2; block[255-payload.size()]=0;
    std::copy(payload.begin(),payload.end(),block.end()-payload.size());
    const auto testRequest=activation::Wide(activation::Base64Encode(
        activation::PublicRecover(block,keypatch::kPatchedModulus)));
    const auto fixedResponse=keypatch::GenerateResponse(testRequest,L"User",L"Personal",testSerial,1700000000);
    Require(fixedResponse=="g9LE/bSWS6c0ipEtBH4SFI1ofKAeETq8l8DwPLEwrOrsEGb6KCWQEm/sBeKT6JTvroSSLa20lyFEmXmgDerY/RuBur70n0ofREi3U0zKhGR5VLlM+1IQK6zyU+9irCv5/3MAjCdU6A2Yy557l4EEUPFyUe8VTWdCZoRSW5Smiett8bxAKGWO/fizUMqJshaZUgdMmhNn4wr/Vk6tJHLkwUYqIHNrgMTU08R4Q1E8hvKV2lcEZ/3ENV8Y3mZshBLJXV42ig/ILj4yz/EbQ2MVjWyehvUG0HBQyFyN6vWn0Qu08Lbz+fbAXbSHfXJMupEfmMG0BUkkn31rPFjtY16MYg==","Independent response vector differs");

    auto click=[&](int id) { SendMessageW(app.window,WM_COMMAND,MAKEWPARAM(id,BN_CLICKED),reinterpret_cast<LPARAM>(app.Get(id))); };
    app.Set(Serial,testSerial); app.Set(Request,testRequest);
    click(Inspect); click(Calculate);
    Require(app.errorCount==0,"GUI calculation failed");
    auto fields=keypatch::RecoverResponse(app.Text(Response));
    Require(keypatch::StringField(fields,"DI")==testDevice,"GUI response device mismatch");
    Require(IsWindowEnabled(app.Get(CopyResponse))!=FALSE,"Copy should be enabled");
    app.Set(Name,L"Changed"); Require(app.Text(Response).empty(),"Name change retained old response");
    Require(!IsWindowEnabled(app.Get(CopyResponse)),"Copy should be disabled");
    click(Calculate); Require(keypatch::StringField(keypatch::RecoverResponse(app.Text(Response)),"N")=="Changed","Name was not used");
    app.Set(Request,app.Text(Request)+L"\n"); Require(app.Text(Response).empty(),"Request change retained old response");
    app.state=keypatch::State::Original; app.SyncButtons();
    Require(IsWindowEnabled(app.Get(Patch)) && !IsWindowEnabled(app.Get(Restore)),"Original button state");
    app.state=keypatch::State::Patched; app.SyncButtons();
    Require(!IsWindowEnabled(app.Get(Patch)) && IsWindowEnabled(app.Get(Restore)),"Patched button state");
    app.Set(PathBox,L"C:\\changed"); Require(!IsWindowEnabled(app.Get(Patch)) && !IsWindowEnabled(app.Get(Restore)),"Directory change state");
    const auto checkDirectory=DefaultDirectory();
    const auto expectedState=keypatch::InstallationState(checkDirectory);
    app.Set(PathBox,checkDirectory.wstring());
    app.StartJob(Check);
    Require(app.busy && !IsWindowEnabled(app.Get(PathBox)),"Background check did not disable directory edits");
    SendMessageW(app.window,WM_CLOSE,0,0);
    Require(IsWindow(app.window)!=FALSE,"Window closed during file operation");
    const auto deadline=GetTickCount64()+10000;
    while (app.busy && GetTickCount64()<deadline) {
        MSG pending{};
        while (PeekMessageW(&pending,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&pending); DispatchMessageW(&pending); }
        if (app.busy) MsgWaitForMultipleObjects(0,nullptr,FALSE,50,QS_ALLINPUT);
    }
    Require(!app.busy && app.state==expectedState,"Background version check failed");
    for (const auto size : {SIZE{1000,870},SIZE{850,760}}) {
        SetWindowPos(app.window,nullptr,0,0,app.Scale(size.cx),app.Scale(size.cy),SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE);
        app.Layout(); RECT bounds{}; GetClientRect(app.window,&bounds);
        for (const auto& control : app.controls) {
            RECT rect{}; GetWindowRect(control.second,&rect); MapWindowPoints(nullptr,app.window,reinterpret_cast<POINT*>(&rect),2);
            Require(rect.left>=0 && rect.top>=0 && rect.right<=bounds.right && rect.bottom<=bounds.bottom && rect.right>rect.left && rect.bottom>rect.top,"GUI control outside client area");
        }
    }
    // Exercise the same GetMessage/IsDialogMessage path as the interactive window.
    PostMessageW(app.window,WM_APP+2,0,0); PostQuitMessage(0);
    MSG message{}; int dispatched=0; BOOL result;
    while ((result=GetMessageW(&message,nullptr,0,0))>0) {
        if (!IsDialogMessageW(app.window,&message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        ++dispatched;
    }
    Require(result==0 && dispatched>0,"Native message loop failed");
    Require(app.errorCount==0,"Unexpected GUI error");
}
int Run(HINSTANCE instance,int show,bool testing) {
    INITCOMMONCONTROLSEX common{sizeof(common),ICC_STANDARD_CLASSES}; InitCommonControlsEx(&common);
    SetProcessDPIAware();
    const auto initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) keypatch::Fail("无法初始化原生目录选择组件。");
    struct ComScope { ~ComScope() { CoUninitialize(); } } comScope;
    App app; app.testing=testing;
    WNDCLASSEXW wc{sizeof(wc)}; wc.hInstance=instance; wc.lpfnWndProc=WindowProc; wc.lpszClassName=ClassName;
    wc.hCursor=LoadCursorW(nullptr,IDC_ARROW); wc.hIcon=LoadIconW(nullptr,IDI_APPLICATION); wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    keypatch::WinCheck(RegisterClassExW(&wc)!=0,"无法注册窗口");
    HDC dc=GetDC(nullptr); app.dpi=GetDeviceCaps(dc,LOGPIXELSY); ReleaseDC(nullptr,dc);
    RECT work{}; SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);
    const int width=std::min(app.Scale(1000),static_cast<int>(work.right-work.left));
    const int height=std::min(app.Scale(870),static_cast<int>(work.bottom-work.top));
    HWND window=CreateWindowExW(WS_EX_CONTROLPARENT,ClassName,L"Navicat Keypatch 18.0.6 · C++",WS_OVERLAPPEDWINDOW,
        work.left+(work.right-work.left-width)/2,work.top+(work.bottom-work.top-height)/2,width,height,nullptr,nullptr,instance,&app);
    keypatch::WinCheck(window!=nullptr,"无法创建主窗口");
    int exitCode=0;
    try {
        if (testing) {
            RunGuiChecks(app);
        } else {
            ShowWindow(window,show); UpdateWindow(window); app.StartJob(Check);
            MSG message{}; BOOL result;
            while ((result=GetMessageW(&message,nullptr,0,0))>0) {
                if (!IsDialogMessageW(window,&message)) { TranslateMessage(&message); DispatchMessageW(&message); }
            }
            if (result<0) exitCode=1;
        }
    } catch (...) {
        if (!testing) MessageBoxW(window,keypatch::ErrorText().c_str(),L"运行失败",MB_OK|MB_ICONERROR);
        exitCode=1;
    }
    if (IsWindow(window)) DestroyWindow(window);
    UnregisterClassW(ClassName,instance);
    return exitCode;
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show) {
    int count=0; LPWSTR* args=CommandLineToArgvW(GetCommandLineW(),&count);
    bool testing=false;
    if (args) {
        if (count==2 && wcscmp(args[1],L"--self-test")==0) testing=true;
        else if (count!=1) { LocalFree(args); return 2; }
        LocalFree(args);
    }
    try { return Run(instance,show,testing); }
    catch (...) {
        if (!testing) MessageBoxW(nullptr,keypatch::ErrorText().c_str(),L"启动失败",MB_OK|MB_ICONERROR);
        return 1;
    }
}
```

\</details\>

### 16.1 编译

打开 Visual Studio 的 **x64 Native Tools Command Prompt**，在源代码所在位置执行：

```bat
cl /nologo /std:c++17 /utf-8 /EHsc /W4 /O2 /MT /DUNICODE /D_UNICODE Keypatch.cpp /Fe:Keypatch.exe /link user32.lib gdi32.lib bcrypt.lib comctl32.lib shell32.lib ole32.lib uuid.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /DYNAMICBASE /NXCOMPAT
```

`/MT` 静态链接 C++ 运行库；`/utf-8` 保证中文源码按 UTF-8 编译；`/MACHINE:X64` 固定 x64 产物。原生控件依赖在代码中声明，DPI 由进程初始化设置。

生成的 `Keypatch.exe` 可单独运行，只依赖 Windows 系统 DLL。

### 16.2 运行隐藏自检

在 PowerShell 执行：

```powershell
$testProcess = Start-Process -FilePath '.\Keypatch.exe' -ArgumentList '--self-test' -WindowStyle Hidden -Wait -PassThru
$testProcess.ExitCode
```

退出码应为 0。这个自检使用合成请求，并与独立模型的固定响应逐字节比较；文件部分只检查状态，不点击补丁或恢复按钮。它还检查修改输入清空旧响应、复制按钮启停、异步检查完成和默认/最小窗口布局。

### 16.3 检查依赖

在同一个开发者命令提示符中执行：

```bat
dumpbin /dependents Keypatch.exe
```

正常导入应为 USER32、GDI32、bcrypt、COMCTL32、SHELL32、ole32、KERNEL32 等系统 DLL。不能仅因程序窗口看起来像原生，就假定它没有打包解释器；导入、文件体积和编译方式应共同核对。

## 17. 怎样逐层验证，而不是只看最后一个结果

### 17.1 算法检查点

| 层次           | 必须得到的结果                           |
|----------------|------------------------------------------|
| DES 固定样本   | `DBB782CE326520FF → 2D7415EDEEFF83B4`    |
| 序列号         | `NAVC25AV5XXP7A5U`                       |
| 原公钥模拟     | 2048 位、e=65537、4553 条指令            |
| 修改后公钥模拟 | 字符 S→T，其他字符保持一致，4553 条指令  |
| 模数变化       | 从 0 起第 240 字节 `4A→4E`，差值 `2^122` |
| 新模数分解     | p=47，q 为 2043 位且通过素性测试         |
| 私有指数       | `eD mod ((p−1)(q−1)) = 1`                |
| 请求解密       | `00 02 PS 00 JSON`，K/DI 原样取得        |
| 响应恢复       | `00 01 FF...00 JSON`，完整 256 字节匹配  |
| 原公钥对新响应 | 不能恢复预期消息                         |

前面的整数测试还覆盖 0、1、47、N′−1、N′−47，避免只验证某个与模数互素的小整数。合成请求由独立库加密，原生响应另用 CNG 恢复，以减少同一实现错误互相抵消的可能。

### 17.2 文件补丁与恢复检查点

先对原版 DLL 的副本测试：应用补丁后，目标完整哈希应等于补丁版哈希，备份仍等于原版哈希。重复应用不能覆盖备份；恢复后目标回到原版哈希，备份保留。

再检查失败分支：未知 DLL 必须拒绝；同名备份内容不匹配必须保留并停止；被占用文件替换失败时，原文件与完整备份必须保持；损坏备份不能用于恢复。不能用“偏移位置的字节变了”代替完整文件验证。

### 17.3 真实产品请求仍需单独确认

隔离模拟证明公钥构造结果，合成请求证明数学和编码实现，原生自检证明窗口与计算接通。它们不自动证明真实产品已经接受响应，也没有覆盖产品的保存转换、再次读取和后续类别/时间状态。

DI 上游没有全部独立复现，所以工具使用真实请求中已经包含的 DI。实际请求兼容性和重启后的状态，应按下一节记录。

## 18. 产品端复现与失败定位

1.  完成原版样本的静态分析和算法复核。
2.  关闭 Navicat，启动刚编译的 Keypatch。
3.  选择真正要测试的安装位置，点击“检查版本”，确认完整文件匹配。
4.  点击“应用补丁并备份”，确认操作完成；写入权限不足时按提示处理。
5.  重新启动 Navicat，使用工具生成的序列号进入手动激活。
6.  取得这次新生成的请求码，粘贴到工具，保持序列号一致。
7.  填写姓名和组织，先“检查请求”，再“计算激活码”。
8.  复制响应到对应的手动激活窗口，观察产品的实际返回。
9.  如果产品接受，再关闭、重新打开，检查状态是否保持。

补丁前的旧请求不能混用。恢复原版公钥后，新参数生成的响应也不再匹配原公钥。

| 现象                        | 排查位置                                     |
|-----------------------------|----------------------------------------------|
| 哈希不符或指令不同          | 样本版本、是否已修改、RVA 与文件偏移是否混淆 |
| 公钥模拟输出不一致          | 初始内存、字符串帮助函数语义、指令白名单     |
| N′ 不能被 47 整除           | Base64 下标、SPKI 解析、模数端序             |
| 请求不满足 `00 02`          | 公钥是否已替换、是否重启、是否用了旧请求     |
| K 不符                      | 当前序列号是否与请求完全对应                 |
| 响应不足 256 字节           | 整数转换时是否丢了前导零                     |
| 回验正确但仍报 `90030002/3` | 原始 K、DI 是否被改写或混用                  |
| 保存或重启后状态不符        | 持久化转换、写入、再次读取和后续状态路径     |
| 补丁或恢复被拒绝            | 文件占用、写入权限、备份完整性               |

这条复现链的每一步都有明确的中间结果：界面事件对应哪个导出，虚表槽对应哪个函数，哪条指令追加哪个字符，字符变化如何落到模数，模数如何得到私有指数，以及响应最终如何被恢复和比较。按这些检查点逐层核对，才能把汇编中的证据和生成器里的计算对应起来。

![](https://attach.52pojie.cn/forum/202611/11/105340ovnntq1lz5axz9id.png)
![](https://attach.52pojie.cn/forum/202611/11/105342mqyv5bt6q6yx6m6x.png)
![](https://attach.52pojie.cn/forum/202611/11/105344z8xoqxlmlyxidmnq.png)
![](https://attach.52pojie.cn/forum/202611/11/105347txnt3ddt3tn3mxx0.png)
注册机源码及程序
[keypatch-18.zip](https://www.52pojie.cn/forum.php?mod=attachment&aid=Mjg5MzAyNXw1MWUwMTIxZHwxNzk0Mzc5MTg5fDB8MjEzNjc5Ng%3D%3D) *(929.18 KB, 下载次数: 2)*

---

原文：<https://www.52pojie.cn/thread-2136796-1-1.html>（吾爱破解论坛，2026-11-11 发布）
