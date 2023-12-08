# Vps__Tracker

VPS_Tracker工具是一款用Python编写的工具，专为攻防演练而设计。其主要功能是帮助用户在海量攻击IP中快速定位红队VPS。在安全测试和模拟攻击的情境下，VPS_Tracker通过扫描IP端口的方式，有效地定位黑客工具，从而精准匹配到红队的存在。通过分析攻击IP的端口信息，VPS_Tracker不仅能够检测潜在的威胁，还能够追溯攻击源头，为网络安全团队提供及时有效的反制手段。

#### 0x01 工具参考

参考知攻善防实验室项目：https://github.com/ChinaRan0/fastbt

#### 0x02支持17个黑客工具的检测规则

```
资产工具：灯塔系统、H资产收集平台、LangSrc、nem
漏洞扫描工具：AWVS、大宝剑、美杜莎红队武器库平台、Nessus、NextScan
漏洞工具：DNSLog平台、XSS Platform、xray反连平台
C2工具：Manjusaka、Viper、Supershell
流量代理工具：NPS、Frp web面板
```

#### 0x03 工具使用说明(1.0)

检测单个IP

```
python3 VPS_Tracker.py -t 127.0.0.1 
```

![图片](https://github.com/GeniusZJL/Vps_tracke/assets/76109016/a44c18ef-5170-4b16-8b97-096beeb71c26)


成功匹配到资产信息后生成result.xlsx

![图片](https://github.com/GeniusZJL/Vps_tracke/assets/76109016/15f06de2-2141-49fe-9b59-e3537802f15e)





 批量多个IP      

```
python3 VPS_Tracker.py -f ip.txt
```
![图片](https://github.com/GeniusZJL/Vps_tracke/assets/76109016/7b223925-854b-4af0-8123-ca9b4d028f40)

成功匹配到资产信息后生成result.xlsx

![图片](https://github.com/GeniusZJL/Vps_tracke/assets/76109016/c21ebaca-1ee3-4fa2-bebd-8e7a832f955e)


全端口扫描(目前扫描速度慢，后续优化)

```
python3 VPS_Tracker.py -t 127.0.0.1 -all 
python3 VPS_Tracker.py -f url.txt -all
```
![图片](https://github.com/GeniusZJL/Vps_tracke/assets/76109016/31e265d2-f5a8-4974-a1ab-0254746367bc)


#### 0x04 免责声明

该开源工具是由作者按照开源许可证发布的，仅供个人学习和研究使用。作者不对您使用该工具所产生的任何后果负任何法律责任。
                 ![图片](https://github.com/GeniusZJL/Vps_tracke/assets/76109016/b773b02a-31b5-4462-8923-8e9c914e6bb9)

