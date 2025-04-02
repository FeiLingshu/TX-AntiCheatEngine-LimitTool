# TX-AntiCheatEngine-LimitTool `腾讯反作弊组件限制工具`  
> ### 本程序仅通过Windows系统原始功能对腾讯反作弊组件进程添加性能限制，无法也永远不会实现削弱或彻底关闭反作弊功能，请各位玩家绿色游戏，不要尝试使用本程序绕过反作弊系统，维护良好游戏环境，从你我做起  

# 程序功能  
- [x] 实现自动检测反作弊相关进程  
- 通过事件触发机制对反作弊组件的启动和关闭进行相应，不进行高频循环，在系统空闲时不会产生额外的性能开销  
- 需确认系统中是否存在AntiCheatExpert Service服务  
</br>

- [x] 高强度容错处理  
- 任意时间节点启动本程序，均可实现对相应进程进行处理（依然建议开机自启）  
- 即使启动时未安装任何腾讯游戏，导致系统中不存在AntiCheatExpert Service服务，程序也不会退出，而是进入后台静默状态，安装任意游戏导致安装AntiCheatExpert Service服务时，程序会由产生的系统事件自动唤醒  
</br>

- [x] 限制进程优先级为最低  
- 通过限制进程优先级，保证前台程序（例如游戏，听歌软件，浏览器等）流畅运行  
</br>

- [x] 自动根据计算机配置设置处理器核心相关性  
- 限制程序只能利用一个或少数几个CPU核心，以限制其处理数据的能力  
- 程序会根据计算机CPU情况，自动分配核心，如果CPU为Intel大小核架构，会将所有小核产生的逻辑处理器分配给反作弊进程（此举是为了保证反作弊进程稳定运行，如果只分配一个小核，有可能会出现小核处理能力差导致任务积压，反作弊进程响应速度过慢，造成游戏弹窗），如果CPU关闭了小核/禁用了Intel超线程技术/非大小核架构，会仅将最后一个逻辑处理器分配给反作弊进程  
- 如果你的CPU能够产生超过64个逻辑处理器（去任务管理器里数框框），请不要使用本程序，微软未对这种情况做良好支持，若强行添加支持会影响程序运行的稳定性，详见[MSDN](https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask?redirectedfrom=MSDN#remarks)相关页面  
</br>

- [x] 配置进程模式为效能模式  
- 限制进程提升CPU频率以获取更快运行速度的请求，并限制进程计时器分辨率，最大限度降低进程在操作系统中的优先级  
- 该功能为核心功能，对反作弊进程的活动产生的限制最大  
- 在Windows 11 22H2前，由于不存在效能模式，操作系统会自动将请求降级为低能耗模式，该模式无法达到与效能模式相同的效果，但依旧能对进程进行有效限制（仍推荐Windows 11 22H2版本及以上），详见[MSDN](https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation#remarks)相关页面  
</br>

# 安装方式
> ### 程序可执行文件在任意位置均可运行，但依然推荐使用Windows任务计划程序配置开启启动，具体配置方式详见[bilibili](https://www.bilibili.com/video/BV1dLfPYsEHx)相关视频



<br></br>
___
> ### **_本程序由作者本人（即 FeiLingshu）原创编写。_**
