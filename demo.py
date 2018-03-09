# -*- coding:utf-8 -*-
import socket
import threading
import ipaddr
import time
import os
import re
import tkinter

'''
1. 判断主机存活
2. TCP全连接扫描开放端口
3. 查询端口对应服务
'''

# 定义全局变量
'''
result 格式  ==>  dict{ip:{port:banner}}
'''
results = {}

class port_scan:
    def __init__(self,ip_segment,threads=500):
        '''
        初始化 ip段 和 最大线程数
        '''
        self.ips = ipaddr.IPNetwork(ip_segment)
        self.threads = threads

    def judge_alive(self,ip):
        '''
        ping 判断主机存活，通过传入 ip 进行判断

        command : ping ip -n 1

        如果返回结果中目标 ip 的个数为 3，则说明一定存活

        否则 不一定存活

        一定存活返回  True
        否则         False
        '''
        ip = str(ip)
        content = os.popen('ping %s -n 1'%ip).read()        # ping 判断
        items = re.findall('\d*\.\d*\.\d*\.\d*',content)    # 匹配 IP
        if items.count(ip) == 3:
            return True
        elif items.count(ip) == 2:
            return False
        else:
            print 'Retry alive scaning'
            judge_alive(ip)

    def tcp_scan(self,ip,port,semaphore):
        '''
        TCP全连接扫描端口是否开放

        传入 ip、port、线程控制数

        开放的端口存入字典 results 中
        '''
        probe = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        try:
            probe.connect((str(ip),port))
            print('Discovered open port %d/tcp on %s'%(int(port),str(ip)))
            out_content.insert('end','[+] Discovered open port %d/tcp on %s\n'%(int(port),str(ip)))
            try:
                probe.send('banner test')
                recv_data = probe.recv(1024)
                if len(recv_data) == 0:
                    recv_data = ''
                results[str(ip)][str(port)] = recv_data
            except:
                results[str(ip)][str(port)] = ''


            probe.close()
            semaphore.release()
        except Exception as e:
            semaphore.release()
            if 'timed out' in str(e):
                pass
            else:
                #print e
                pass
            #print('[-] ' + ip + '\'s port' + str(port) + ' is closed')

    def query(self,port):
        '''
        查询 TCP 端口对应的服务
        '''
        tcp_port_file = open('TCP_Port_to_Service','r')
        contents = tcp_port_file.readlines()
        tcp_port_file.close()
        tcp_correspond = {}
        for line in contents:
            tmp = line.strip('\n')
            key,value = tmp.split('=',1)
            tcp_correspond[key.strip(' ')] = value.strip(' ')

        if str(port) in tcp_correspond:
            return unicode(tcp_correspond[str(port)],'utf-8')
        else:
            return 'unknown'

    def generate_report(self,results,open_file_when_save_finished=False):
        '''
        自动将结果保存为 html 文件
        open_file_when_save_finished = True 表示自动打开文件
        '''
        with open('result.html','w') as f:
            # report 头部（固定内容）
            f.write('''<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
            <html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <title>扫描结果</title>
            <link rel="stylesheet" type="text/css" href="./css/all-base.css">
            <link rel="stylesheet" href="./css/toolstyle.css" type="text/css">
            <body>
            <div class="wrapper"> <!-- 居中 -->
                <!--IcpMain02-begin-->
               <div class="IcpMain02 mt10">

                       <div class="ResultWrap" id="contenthtml">
                            <p class="ResultListHead bg-blue08 col-gray03 clearfix bor-b1s02">
                              <span class="ReListhalf w15-0 tc">ip</span>
                              <span class="ReListhalf w15-0 tc">端口</span>
                              <span class="ReListhalf w15-0 tc">状态</span>

                              <span class="ReListhalf w15-0 tc">服务</span>
                              <span class="ReListhalf w15-0 tc">banner</span></p>
                              <p class="ResultListwrap clearfix bor-b1s02">
                              ''')

            for ip in results:
                for port in results[ip]:
                    state = 'open'
                    service = self.query(port)
                    banner = results[ip][port]
                    if len(banner) == 0:
                        banner = '&nbsp'
                    else:
                        banner = re.sub('<.*?>','',banner)
                        banner = banner.split('\n')[0]

            # 数据部分
                    f.write('''
            <span class="ReListhalf w15-0 tc YaHei fz16 col-blue02 portitem" s="1">%s</span>
            <span class="ReListhalf w15-0 tc col-green02">%s</span>
            <span class="ReListhalf w15-0 tc col-green02">%s</span>
            <span class="ReListhalf w15-0 tc col-green02">%s</span>
            <span class="ReListhalf w15-0 tc col-green02">%s</span>
            <span class="ReListhalf w15-0 tc col-green02">&nbsp</span>

            '''%(ip,str(port),state,service.encode('utf-8'),banner))

            # 尾部（固定内容）
            f.write('''
            </p>
            </div>
            </div>
            </body></html>''')
        f.close()
        if open_file_when_save_finished == True:
            os.system('result.html')
        else:
            pass

    # 主函数
    def main(self,port_range='1-1025',generate_report=True,open_file_when_save_finished=False):
        '''
        传入 3 个参数
        0.端口扫描范围
        1.是否生成报告
        2.是否自动打开生成的报告
        '''
        semaphore = threading.Semaphore(self.threads)    # 最大线程数
        print('Starting Scan at %s'%str(time.strftime('%Y-%m-%d %H:%M:%S %Z')))
        try:
            start_port = int(port_range.split('-')[0].strip(' '))
            end_port = int(port_range.split('-')[1].strip(' ')) + 1
        except:
            start_port = int(port_range)
            end_port = int(port_range) + 1
        out_content.insert('end','\nStarting Scan at %s\n'%str(time.strftime('%Y-%m-%d %H:%M:%S')))
        for ip in self.ips:
            if self.judge_alive(ip):
                # 存活的主机
                print '[+] host %s is up , start port scan'%ip
                out_content.insert('end','[+] host %s is up , start port scan\n'%ip)
                results[str(ip)] = {}   # 如果主机存活就先把 ip 加到 dict 里面
                for port in xrange(start_port,end_port): # 端口扫描范围
                    semaphore.acquire()
                    thread = threading.Thread(target=self.tcp_scan,args=(ip,port,semaphore))
                    thread.start()
                thread.join()
            else:
                pass

        # 输出结果 ip + 端口 + 状态 + 对应服务 + banner
        '''for ip in results:
            for port in results[ip]:
                service = self.query(port)
                print results[ip][port]'''
        if generate_report == True:
            self.generate_report(results, open_file_when_save_finished)
            print '[+] generate report save as result.html'
            out_content.insert('end','[+] generate report save as result.html\n')
        else:
            pass

def frame():
    '''
    图形化界面模块
    '''
    # 运行函数
    def get_text_and_run():
        ip_segment = ip_segment_recv.get()
        if judge_ip(str(ip_segment)) == False:
            out_content.insert('end','[-] 请确认您的 IP_Segment 输入准确无误 \n')
        else:
            threads = max_threads.get()
            if judge_threads(threads) == False:
                out_content.insert('end','[-] 请确认您的 MAX_Threads 输入准确无误 \n')
            else:
                threads = int(threads)
                port_range = port_range_recv.get()
                if judge_port(port_range) == False:
                    out_content.insert('end','[-] 请确认您的PORT_Range 输入准确无误 \n')
                else:
                    instance = port_scan(ip_segment,threads)
                    # 判断勾选项是否选择保存为 html 文件
                    if var.get() == '1' and var1.get() == '0':
                        instance.main(port_range,generate_report=True, open_file_when_save_finished=False)
                    elif var.get() == '1' and var1.get() == '1':
                        instance.main(port_range,generate_report=True, open_file_when_save_finished=True)
                    elif var.get() == '0':
                        instance.main(port_range,generate_report=False)
                    for ip in results:
                        out_content.insert('end','\nReport for %s\n'%str(ip))
                        out_content.insert('end','-----------------------------\n')
                        out_content.insert('end','PORT\tSTATE\tSERVICE\n')
                        for port in results[ip]:
                            out_content.insert('end','%s\topen\t%s\n'%(str(port),instance.query(port)))


    def judge_ip(ip):
        '''
        判断 ip 或者 ip段的格式是否正确
        '''
        try:
            split = ip.split('/')
            new_ip = split[0]
            num = split[1]
            if int(num) > 32 or int(num) < 0:
                return False
            try:
                ips = new_ip.split('.')
                if len(ips) != 4:
                    return false
                for tmp_num in ips:
                    if int(tmp_num) > 255 or int(tmp_num) < 0:
                        return False
            except:
                return False
        except:
            try:
                ips = ip.split('.')
                if len(ips) != 4:
                    return false
                for tmp_num in ips:
                    if int(tmp_num) > 255 or int(tmp_num) < 0:
                        return False
            except:
                return False
        return True
    def judge_threads(threads):
        '''
        判断 threads 输入是否有误
        '''
        try:
            num = int(threads)
            if num <= 0:
                return False
        except:
            return False
        return True
    def judge_port(port_range):
        try:
            start_port = int(port_range.split('-')[0].strip(' '))
            end_port = int(port_range.split('-')[1].strip(' ')) + 1
            if start_port > end_port:
                return False
            if start_port < 0 or start_port > 65535 or end_port < 0 or end_port > 65535:
                return False
        except:
            try:
                port = int(port_range)
                if port < 0 or port > 65535:
                    return False
            except:
                return False
        return True

    # 布局
    window = tkinter.Tk(className='Port Scan')
    window.geometry('1200x800')
    window.iconbitmap('fav.ico')
    # 输入 IP 段的标签
    ip_segment_label = tkinter.Label(window,text='IP_Segment : ',font = ('Arial',15),width = 15, height=2,justify='left')
    ip_segment_label.place(x=-10,y=0,anchor='nw')
    # 输入最大线程数的标签
    threads_label = tkinter.Label(window,text='MAX_Threads : ',font = ('Arial',15),width = 15, height=2,justify='left')
    threads_label.place(x=0,y=50,anchor='nw')
    # 输入端口范围标签
    port_label = tkinter.Label(window,text='PORT_Range : ',font = ('Arial',15),width = 15, height=2,justify='left')
    port_label.place(x=0,y=100,anchor='nw')
    # 接收输入的 IP 段
    ip_segment_recv = tkinter.Entry(window,font = ('Arial',15))
    ip_segment_recv.place(x=170,y=12,anchor='nw')
    # 接收输入的最大线程数
    max_threads = tkinter.Entry(window,font = ('Arial',15))
    max_threads.place(x=170,y=62,anchor='nw')
    # 接收端口扫描范围
    port_range_recv = tkinter.Entry(window,font = ('Arial',15))
    port_range_recv.place(x=170,y=112,anchor='nw')
    # 输出扫描内容的部分
    global out_content  # 全局，用于将过程展示出来
    out_content = tkinter.Text(window,height=20,width=107,font = ('Arial',15))
    out_content.place(x=8,y=170,anchor='nw')
    # 勾选项，是否将结果保存为 html 文件
    var = tkinter.StringVar()
    save_result_as_html = tkinter.Checkbutton(window,text = '是否将扫描结果保存为 result.html',variable = var,onvalue = 1,offvalue=0,font = ('楷体',15))
    save_result_as_html.select()    # 默认设置为选择状态
    save_result_as_html.place(x=800,y=12,anchor='nw')
    #  是否打开保存的文件
    var1 = tkinter.StringVar()
    save_result_as_html = tkinter.Checkbutton(window,text = '是否自动打开 result.html 文件',variable = var1,onvalue = 1,offvalue=0,font = ('楷体',15))
    save_result_as_html.deselect()    # 默认设置为选择状态
    save_result_as_html.place(x=800,y=42,anchor='nw')
    # 开始扫描按钮（先判断最大线程数和标签是否填写）
    Button = tkinter.Button(window,text='SCAN',font = ('黑体',20),width = 15,height = 2,command=get_text_and_run)
    Button.place(x=510,y=670,anchor='nw')
    window.mainloop(n=0)

if __name__ == '__main__':
    frame()
