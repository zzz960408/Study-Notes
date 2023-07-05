#### 一.下载准备

本次所使用系统为centos7.4，kubernetes版本为1.20，etcd版本为3.4.3，推荐使用相同版本，不会产生兼容或者其他问题

##### 1.服务器准备

因本次准备多master节点集群，故此最少准备5台服务器，服务器ip如下

```
master1 192.168.65.130
master2 192.168.65.131
master3 192.168.65.132
node1   192.168.65.133
node2   192.168.65.134
```

##### 2.服务器文件夹创建

在服务器上创建以下文件夹：

```
mkdir /etc/etcd/{bin,cfg,ssl,data} -p    #etcd所要使用的文件夹
mkdir /usr/bin/cfssl #建立cfssl的文件夹
mkdir /etc/kubernetes/{bin,cfg,logs,ssl} #k8s所要使用的文件夹
```

##### 3.etcd下载

下载etcd的对应版本https://github.com/etcd-io/etcd，在releases中选择对应的版本，kubernetesv1.20对应最高etcd版本为3.4.x,解压后将etcd、etcdctl上传至/etc/etcd/bin目录下，如果是直接上传的两个文件，需要执行

```
chmod +x  /etc/etcd/bin/   #对二进制程序给予执行权限，否则将无法正常启动，添加到守护进程后，也将报x203的错误
```

##### 4.kubernetes下载

下载kubernetes的二进制安装包，下载地址在https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG ，releases中只有源码，二进制包需要到Changelog中下载，点开需要的版本的变更日志，现在对应的系统及内核版本，下载好后将压缩包上传至服务器上，解压，将Server\bin文件夹中的kube-apiserver、kube-controller-manager 和 kube-scheduler、kubelet、kubectl、kube-proxy复制到/etc/kubernetes/bin下，直接上传的两个文件，需要执行

```
chmod +x  /etc/kubernetes/bin/   #对二进制程序给予执行权限，否则将无法正常启动，添加到守护进程后，也将报x203的错误
```

##### 5.服务器环境准备

打开服务器执行如下命令

```
yum install  -y  telnet  wget  ntpdate net-tools.x86_64   #安装服务器环境所需软件
ntpdate ntp.ntsc.ac.cn     #调整服务器对时，也可以换成其他的授时服务器
hostnamectl set-hostname  master1      #对每台服务器名称分别进行设置
hostname $(cat /etc/hostname)   #使命令即时生效，否则只能重启后才生效

cat >> /etc/hosts << EOF
192.168.65.130 master1
192.168.65.131 master2
192.168.65.132 master3
192.168.65.133 node1
192.168.65.134 node2
EOF                                #将服务器名称与ip的对应输入host文件

cat >> /etc/sysctl.d/k8s.conf << EOF
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1 
EOF                                  #预定义kubernetes所使用的内核参数
sysctl --system

cat >> /etc/security/limits.conf <<EOF
soft nofile 65535
hard nofile 65535
soft noproc 65535
hard noproc 65535
soft memlock unlimited
hard memlock unlimited
EOF                            #调整资源限制

sed -i 's/enforcing/disabled/' /etc/selinux/config
setenforce 0       #关闭selinux，也可以单独放行

sed -ri 's/.*swap.*/#&/' /etc/fstab
swapoff -a         #关闭swap，如果不关闭需要单独设置kubelet，否则可能会有冲突，启动报错

systemctl disable firewalld & systemctl stop firewalld   #关闭防火墙，也可以放行
```

##### 6.下载cfssl工具

进入/usr/bin/cfssl文件夹，执行以下命令

```
#下载cfssl工具并给予执行权限
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
chmod +x /usr/bin/cfssl*
```

##### 7.生成CA根证书

进入/usr/bin/cfssl文件夹，执行以下命令

```
cat > ca-csr.json <<EOF
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "system"
        }
    ]
}
EOF


./cfssl gencert -initca ca-csr.json | ./cfssljson -bare ca -
```

##### 8.服务器ssh密钥配置

每台服务器输入以下命令

```
ssh-keygen -t rsa  #让输入时候直接回车默认值就可以，生成ssh公钥私钥文件
cd ~/.ssh  #进入ssh密钥文件夹，其中有id_rsa（私钥）、id_rsa.pub（公钥）
vi  authorized_key         #将每台服务器的id_rsa.pub文件内的值都复制进去，保存，这样就完成了ssh免密登录
```

#### 二.etcd安装配置

##### 1.ssl证书生成

进入/usr/bin/cfssl目录下，输入以下命令

```
cat  > etcd-csr.json <<EOF 
{
    "CN": "kubernetes",
    "hosts": [
        "127.0.0.1",
        "192.168.65.130",
        "192.168.65.131",
        "192.168.65.132",
		"192.168.65.133",
		"192.168.65.134"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "system"
        }
    ]
}
EOF                               

cat  > etcd-csr.json <<EOF
{
    "CN": "kubernetes",
    "hosts": [
        "127.0.0.1",
        "192.168.65.130",
        "192.168.65.131",
        "192.168.65.132",
		"192.168.65.133",
		"192.168.65.134"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "system"
        }
    ]
}
EOF

./cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes etcd-csr.json | ./cfssljson -bare etcd   #生成etcd所使用的的证书，-profile要与CN一致

cp *.pem  /etc/etcd/ssl        #复制证书到etcd目录下
#复制完成后，将证书复制到每台服务器上
```

##### 2.etcd安装配置

输入以下命令

```
#分别在每台服务器执行下面的命令，根据服务器ip不同修改不同的ip，因为etcd集群没有master worker的区别，所以除了ip和etcd name不同，其他都一致
cat > /etc/etcd/cfg/etcd.conf << EOF
#[Member]
ETCD_NAME="etcd1"                                 #每台服务器配置不同的etcd name
ETCD_DATA_DIR="/etc/etcd/data"
ETCD_LISTEN_PEER_URLS="https://192.168.65.130:2380"       #当前服务器ip
ETCD_LISTEN_CLIENT_URLS="https://192.168.65.130:2379"     #当前服务器ip
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.65.130:2380"  #当前服务器ip
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.65.130:2379"     #当前服务器ip
ETCD_INITIAL_CLUSTER="etcd1=https://192.168.65.150:2380,etcd2=https://192.168.65.131:2380,etcd3=https://192.168.65.132:2380",etcd4=https://192.168.65.133:2380",etcd5=https://192.168.65.134:2380"
ETCD_INITIAL_CLUSTER_TOKEN="cluster1"   #越简单越好，最好别用-符号，疑似会出bug报集群id不一致的错误
ETCD_INITIAL_CLUSTER_STATE="new"    
EOF                


#创建etcd的守护进程，这个每台服务器一致
cat > /usr/lib/systemd/system/etcd.service << EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
EnvironmentFile=/etc/etcd/cfg/etcd.conf
ExecStart=/etc/etcd/bin/etcd \
--cert-file=/etc/etcd/ssl/etcd.pem \
--key-file=/etc/etcd/ssl/etcd-key.pem \
--trusted-ca-file=/etc/etcd/ssl/ca.pem \
--peer-cert-file=/etc/etcd/ssl/etcd.pem \
--peer-key-file=/etc/etcd/ssl/etcd-key.pem \
--peer-trusted-ca-file=/etc/etcd/ssl/ca.pem \
--logger=zap
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF


#启动etcd并设置开机启动
systemctl daemon-reload && systemctl start etcd && systemctl enable etcd


#输入以下命令查看集群各服务器状态
/etc/etcd/bin/etcdctl --endpoints=https://192.168.65.130:2379,https://192.168.65.131:2379,https://192.168.65.132:2379,https://192.168.65.133:2379,https://192.168.65.134:2379 \
--cert=/etc/etcd/ssl/etcd.pem \
--key=/etc/etcd/ssl/etcd-key.pem \
--cacert=/etc/etcd/ssl/ca.pem \
member list --write-out=table
```

#### 三.kubernetes安装配置

##### 1.安装docker

kubernetes官方在1.20之后弃用了dockershim，最终于1.24版本移除了dockershim，虽然还是可以用cri-docker来进行一个中间支持，但是还是不如原生使用好，本次安装使用的kubernetes版本为1.20,故此仍然使用docker来做为k8s的容器使用

因本次重点为k8s，故docker使用yum简单操作安装，命令行输入以下命令

```
yum install -y yum-utils  #安装yum工具包
yum-config-manager \
    --add-repo \
    https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo    #配置安装docker的仓库为aliyun的
yum makecache fast #更新yum索引
yum install docker-ce docker-ce-cli containerd.io   #安装docker，ce为docker社区版

sudo mkdir -p /etc/docker     

sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "debug": true,
"log-driver": "json-file",
"log-opts": {
"max-size": "10m",
"max-file": "3"
},
"exec-opts": ["native.cgroupdriver=systemd"],
 "registry-mirrors": ["https://qlu6ep7r.mirror.aliyuncs.com"]   #该地址为aliyun  docker镜像加速地址，可使用自己的
}
EOF          

sudo systemctl daemon-reload
sudo systemctl restart docker
sudo systemctl enable docker
```

##### 2.安装kubernetes集群中的master机器

master机器为192.168.65.130-132 三台机器，因为涉及集群的master选举，所以一般来说master机器都是要使用1.3.5.7这样的奇数，本次所使用三台master设置，如果需要建立高可用集群，可以建立vip后，将配置里的相应ip设置都修改为vip，直接就是高可用集群

为了方便操作，kubelet和kubeproxy都直接在master1安装完成后，复制到其他机器

###### 1.部署kube-apiserver

master1服务器执行以下命令

```
cd   /usr/bin/cfssl    


cat > server-csr.json << EOF
{
    "CN": "kubernetes",
    "hosts": [
      "10.0.0.1",
      "127.0.0.1",
      "192.168.65.130",
      "192.168.65.131",
      "192.168.65.132",
      "192.168.65.133",                                      #将所有相关节点的服务器ip全部填入，如果有vip一并填入
      "192.168.65.134",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "BeiJing",
            "ST": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF                   #生成后记得cat server-csr.json检查文件是否有不显示的错误字符，否则可能会生成证书时报错
./cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes server-csr.json | ./cfssljson -bare server     #执行生成证书
cp   /usr/bin/cfssl/server*pem   /etc/kubernetes/ssl/     #将生成的证书复制至k8s文件夹下



cat > /etc/kubernetes/cfg/kube-apiserver.conf << EOF
KUBE_APISERVER_OPTS="--logtostderr=false \\
--v=5 \\                  #日志等级
--log-dir=/etc/kubernetes/logs \\     #日志路径
--etcd-servers=https://192.168.65.130:2379,https://192.168.65.131:2379,https://192.168.65.132:2379,https://192.168.65.133:2379,https://192.168.65.134:2379 \\      #之前所安装的etcd集群的各个机器的路径
--bind-address=192.168.65.130 \\           #监听地址
--secure-port=6443 \\                       #apiserver绑定端口
--advertise-address=192.168.65.130 \\    #集群通告地址
--allow-privileged=true \\
--service-cluster-ip-range=10.0.0.0/24 \\    #Service虚拟IP地址段，以CIDR格式表示，例如10.0.0.0/24，该IP范围不能与物理机的IP地址有重合，跟后面的网络插件相关，如果要安装flannel，需要注意要与yaml文件中一致
--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota,NodeRestriction \\
--authorization-mode=RBAC,Node \\
--enable-bootstrap-token-auth=true \\
--token-auth-file=/etc/kubernetes/cfg/token.csv \\    #bootstrap token文件
--service-node-port-range=30000-32767 \\
--kubelet-client-certificate=/etc/kubernetes/ssl/server.pem \\
--kubelet-client-key=/etc/kubernetes/ssl/server-key.pem \\
--tls-cert-file=/etc/kubernetes/ssl/server.pem  \\
--tls-private-key-file=/etc/kubernetes/ssl/server-key.pem \\
--client-ca-file=/etc/kubernetes/ssl/ca.pem \\
--service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \\
--service-account-issuer=api \\
--service-account-signing-key-file=/etc/kubernetes/ssl/server-key.pem \\
--etcd-cafile=/etc/etcd/ssl/ca.pem \\
--etcd-certfile=/etc/etcd/ssl/etcd.pem \\
--etcd-keyfile=/etc/etcd/ssl/etcd-key.pem \\
--requestheader-client-ca-file=/etc/kubernetes/ssl/ca.pem \\
--proxy-client-cert-file=/etc/kubernetes/ssl/server.pem \\
--proxy-client-key-file=/etc/kubernetes/ssl/server-key.pem \\
--requestheader-allowed-names=kubernetes \\
--requestheader-extra-headers-prefix=X-Remote-Extra- \\
--requestheader-group-headers=X-Remote-Group \\
--requestheader-username-headers=X-Remote-User \\
--enable-aggregator-routing=true \\
--audit-log-maxage=30 \\
--audit-log-maxbackup=3 \\
--audit-log-maxsize=100 \\
--audit-log-path=/etc/kubernetes/logs/k8s-audit.log"
EOF


cat > /etc/kubernetes/cfg/token.csv << EOF
4136692876ad4b01bb9dd0988480ebba,kubelet-bootstrap,10001,"system:node-bootstrapper"
EOF                    #其中第一个数值可以自行替换自己生成的，head -c 16 /dev/urandom | od -An -t x | tr -d ' '


cat > /usr/lib/systemd/system/kube-apiserver.service << EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=/etc/kubernetes/cfg/kube-apiserver.conf
ExecStart=/etc/kubernetes/bin/kube-apiserver \$KUBE_APISERVER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF               #生成kube-apiserver的守护进程

systemctl daemon-reload & systemctl start kube-apiserver & systemctl enable kube-apiserver
systemctl status kube-apiserver    #查看进程状态

```

###### 2.部署kube-controller-manager

master1服务器执行以下命令

```

cat > /etc/kubernetes/cfg/kube-controller-manager.conf << EOF
KUBE_CONTROLLER_MANAGER_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/etc/kubernetes/logs \\
--leader-elect=true \\
--kubeconfig=/etc/kubernetes/cfg/kube-controller-manager.kubeconfig \\
--bind-address=127.0.0.1 \\
--allocate-node-cidrs=true \\
--cluster-cidr=10.244.0.0/16 \\
--service-cluster-ip-range=10.0.0.0/24 \\
--cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem \\
--cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem  \\
--root-ca-file=/etc/kubernetes/ssl/ca.pem \\
--service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem \\
--cluster-signing-duration=87600h0m0s"
EOF



cat  > /etc/kubernetes/cfg/kube-controller-manager.kubeconfig  << EOF
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0t
    server: https://192.168.65.130:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kube-controller-manager
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: kube-controller-manager
  user:
    client-certificate-data: LS0t
    client-key-data: LS0t
EOF

#生成kube-controller-manager的证书
cat > kube-controller-manager-csr.json << EOF
{
  "CN": "system:kube-controller-manager",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing", 
      "ST": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

./cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | ./cfssljson -bare kube-controller-manager
cp    /usr/bin/cfssl/kube-controller-manager*pem   /etc/kubernetes/ssl/  #复制证书

mv /etc/kubernetes/bin/kubectl  /usr/bin/kubectl    #将kubectl转移至/usr/bin目录下
chmod +x  /usr/bin/kubectl    #赋予执行权限

KUBE_CONFIG="/etc/kubernetes/cfg/kube-controller-manager.kubeconfig"     #赋予环境变量

KUBE_APISERVER="https://192.168.65.130:6443"        #赋予环境变量


kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}

kubectl config set-credentials kube-controller-manager \
  --client-certificate=/etc/kubernetes/ssl/kube-controller-manager.pem \
  --client-key=/etc/kubernetes/ssl/kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-controller-manager \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}



#创建kube-controller-manager的守护进程
cat > /usr/lib/systemd/system/kube-controller-manager.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes
After=kube-apiserver.service
Requires=kube-apiserver.service

[Service]
EnvironmentFile=/etc/kubernetes/cfg/kube-controller-manager.conf
ExecStart=/etc/kubernetes/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload & systemctl start kube-controller-manager & systemctl enable kube-controller-manager
systemctl status kube-controller-manager    #查看进程状态

```

###### 3.部署kube-scheduler

master1服务器执行以下命令

```
cat > /etc/kubernetes/cfg/kube-scheduler.conf << EOF
KUBE_SCHEDULER_OPTS="--logtostderr=false \\
--v=5 \\
--log-dir=/etc/kubernetes/logs \\
--leader-elect \\
--kubeconfig=/etc/kubernetes/cfg/kube-scheduler.kubeconfig \\
--bind-address=127.0.0.1"
EOF



cat > /etc/kubernetes/cfg/kube-scheduler.kubeconfig  <<EOF
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0t
    server: https://192.168.65.130:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kube-scheduler
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: kube-scheduler
  user:
    client-certificate-data: LS0t
    client-key-data: LS0t
EOF


cd   /usr/bincfssl

#生成证书
cat > kube-scheduler-csr.json << EOF
{
  "CN": "system:kube-scheduler",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

./cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-scheduler-csr.json | ./cfssljson -bare kube-scheduler

cp   /usr/bin/cfssl/kube-scheduler*pem    /etc/kubernetes/ssl/   #复制证书


KUBE_CONFIG="/etc/kubernetes/cfg/kube-scheduler.kubeconfig"
KUBE_APISERVER="https://192.168.65.130:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-credentials kube-scheduler \
  --client-certificate=/etc/kubernetes/ssl/kube-scheduler.pem \
  --client-key=/etc/kubernetes/ssl/kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-scheduler \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}


#创建守护进程
cat > /usr/lib/systemd/system/kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes
After=kube-apiserver.service
Requires=kube-apiserver.service

[Service]
EnvironmentFile=/etc/kubernetes/cfg/kube-scheduler.conf
ExecStart=/etc/kubernetes/bin/kube-scheduler \$KUBE_SCHEDULER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload & systemctl start kube-scheduler & systemctl enable kube-scheduler
systemctl status kube-scheduler    #查看进程状态

#创建kubectl 连接集群的证书
cat > admin-csr.json << EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

./cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | ./cfssljson -bare admin
cp  /usr/bin/cfssl/admin*pem    /etc/kubernetes/ssl/   #复制证书


#生成 kubeconfig 文件
mkdir /root/.kube

KUBE_CONFIG="/root/.kube/config"
KUBE_APISERVER="https://192.168.65.130:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-credentials cluster-admin \
  --client-certificate=/etc/kubernetes/ssl/admin.pem \
  --client-key=/etc/kubernetes/ssl/admin-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user=cluster-admin \
  --kubeconfig=${KUBE_CONFIG}
  
#会生成/root/.kube/config文件
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}

#此时就可以使用kubectl命令了
kubectl get cs    #查看当前集群组件状态


#授权kubelet-bootstrap用户允许请求证书
kubectl create clusterrolebinding kubelet-bootstrap \
--clusterrole=system:node-bootstrapper \
--user=kubelet-bootstrap
```

###### 4.部署kubelet

master1服务器执行以下命令

```
cat > /etc/kubernetes/cfg/kubelet.conf << EOF
KUBELET_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/etc/kubernetes/logs \\
--hostname-override=master1 \\                    #设置在集群中本节点的名称，唯一，每个节点不同
--network-plugin=cni \\                                   #启用cni网络
--kubeconfig=/etc/kubernetes/cfg/kubelet.kubeconfig \\    #本身不存在，设置该路径为文件生成地址
--bootstrap-kubeconfig=/etc/kubernetes/cfg/bootstrap.kubeconfig \\   #首次启动，自动申请证书
--config=/etc/kubernetes/cfg/kubelet-config.yml \\
--cert-dir=/etc/kubernetes/ssl \\            
--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google-containers/pause-amd64:3.0"
EOF


cat > /etc/kubernetes/cfg/kubelet.kubeconfig  <<EOF
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0t
    server: https://192.168.65.130:6443
  name: default-cluster
contexts:
- context:
    cluster: default-cluster
    namespace: default
    user: default-auth
  name: default-context
current-context: default-context
kind: Config
preferences: {}
users:
- name: default-auth
  user:
    client-certificate: /etc/kubernetes/ssl/kubelet-client-current.pem     #本身不存在，自动申请
    client-key: /etc/kubernetes/ssl/kubelet-client-current.pem            #本身不存在，自动申请
EOF


cat > /etc/kubernetes/cfg/kubelet-config.yml << EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
port: 10250
readOnlyPort: 10255
cgroupDriver: systemd                           #注意要与docker中配置一致，否则会启动报错
clusterDNS:
- 10.0.0.2
clusterDomain: cluster.local 
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/ssl/ca.pem 
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
maxOpenFiles: 1000000
maxPods: 110
EOF



KUBE_CONFIG="/etc/kubernetes/cfg/bootstrap.kubeconfig"
KUBE_APISERVER="https://192.168.65.130:6443"    # apiserver IP:PORT
TOKEN="4136692876ad4b01bb9dd0988480ebba"        # 与token.csv里保持一致  /etc/kubernetes/cfg/token.csv

kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-credentials "kubelet-bootstrap" \
  --token=${TOKEN} \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user="kubelet-bootstrap" \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}      # 会生成bootstrap.kubeconfig文件



#生成守护进程
cat > /usr/lib/systemd/system/kubelet.service << EOF
[Unit]
Description=Kubernetes Kubelet
After=docker.service

[Service]
EnvironmentFile=/etc/kubernetes/cfg/kubelet.conf
ExecStart=/etc/kubernetes/bin/kubelet \$KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload & systemctl start kubelet & systemctl enable kubelet
systemctl status kubelet    #查看进程状态



#启动kubelet守护进程后，可以查看kubelet证书请求
kubectl get csr

#name为上面命令所返回的kubelet证书申请，状态为Pending则是申请中
kubectl certificate approve   name    #通过申请

#查看节点
kubectl get nodes    #通过证书申请后，则可查看到节点，由于网络组件还没有安装，状态为not ready
```

###### 5.部署kubeproxy

在master1服务器执行下面命令

```
cat > /etc/kubernetes/cfg/kube-proxy.conf << EOF
KUBE_PROXY_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/etc/kubernetes/logs \\
--config=/etc/kubernetes/cfg/kube-proxy-config.yml"
EOF



cat > /etc/kubernetes/cfg/kube-proxy-config.yml << EOF
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
clientConnection:
  kubeconfig: /etc/kubernetes/cfg/kube-proxy.kubeconfig
hostnameOverride: master1
clusterCIDR: 10.244.0.0/16
EOF


#生成kube-proxy证书
cd   /usr/bin/cfssl

cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF

./cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | ./cfssljson -bare kube-proxy
cp  /usr/bin/cfssl/kube-proxy*prm /etc/kubernetes/ssl/   #复制证书



#生成kube-proxy.kubeconfig文件
KUBE_CONFIG="/etc/kubernetes/cfg/kube-proxy.kubeconfig"
KUBE_APISERVER="https://192.168.65.130:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-credentials kube-proxy \
  --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
  --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=${KUBE_CONFIG}
  
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}
# 会生成kube-proxy.kubeconfig文件



#生成kube-proxy的守护进程
cat > /usr/lib/systemd/system/kube-proxy.service << EOF
[Unit]
Description=Kubernetes Proxy
After=network.target
Requires=network.service

[Service]
EnvironmentFile=/etc/kubernetes/cfg/kube-proxy.conf
ExecStart=/etc/kubernetes/bin/kube-proxy \$KUBE_PROXY_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload & systemctl start kubeproxy & systemctl enable kubeproxy
systemctl status kubeproxy    #查看进程状态
```

###### 6.安装网络组件

通常可以选择flannel和Calico，本次使用Calico

```
#直接使用默认设置安装Calico，也可以wget下载配置文件后安装
kubectl apply -f https://docs.projectcalico.org/archive/v3.14/manifests/calico.yaml

kubectl get nodes  #等待一会后，可以看到节点已经是ready了
```

###### 7.授权apiserver访问kubelet

在master1上执行

```
cat > apiserver-to-kubelet-rbac.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
      - pods/log
    verbs:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
EOF

kubectl apply -f apiserver-to-kubelet-rbac.yaml   
```

##### 3.新增master节点

新增master2、master3两台服务器到集群中为master节点

以下命令在master2服务器中执行，master3服务器也是一样的

```
#复制文件到master2服务器，ip根据自己情况自行修改
scp -r /etc/kubernetes/ root@192.168.65.131:/etc/kubernetes/
scp /usr/lib/systemd/system/kube* root@192.168.65.131:/usr/lib/systemd/system
scp /usr/bin/kubectl  root@192.168.65.131:/usr/bin
scp -r ~/.kube root@192.168.65.131:~

#清除无效文件
rm -rf   /etc/kubernetes/logs/*
rm -f /etc/kubernetes/cfg/kubelet.kubeconfig 
rm -f /etc/kubernetes/ssl/kubelet*



#修改下列项
# k8s-master2节点执行
vi /etc/kubernetes/cfg/kube-apiserver.conf 
...
--bind-address=192.168.65.131 \
--advertise-address=192.168.65.131 \
...

vi /etc/kubernetes/cfg/kube-controller-manager.kubeconfig
server: https://192.168.65.131:6443

vi /etc/kubernetes/cfg/kube-scheduler.kubeconfig
server: https://192.168.65.131:6443

vi /etc/kubernetes/cfg/kubelet.conf
--hostname-override=master2

vi /etc/kubernetes/cfg/kube-proxy-config.yml
hostnameOverride: master2

vi ~/.kube/config
...
server: https://192.168.65.131:6443


#设置守护进程
systemctl daemon-reload
systemctl start kube-apiserver kube-controller-manager kube-scheduler kubelet kube-proxy
systemctl enable kube-apiserver kube-controller-manager kube-scheduler kubelet kube-proxy
systemctl status kube-apiserver kube-controller-manager kube-scheduler kubelet kube-proxy   #查看守护进程状态



#查看集群组件状态
kubectl get cs

#在master1服务器执行
kubectl get csr     #查看master2证书申请
kubectl certificate approve    name    #name为上面命令所返回的申请name


kubectl get nodes    #执行后发现多出master2节点



#此时，加入master2节点成功，master3可使用同样方法加入，更多master节点也是一样的，最好保持奇数个master节点
```

##### 4.新增worker节点

新增node节点为node1，node2可按照相同方法加入到集群，方法如下

```
#从master1服务器复制文件到node1
scp -r /etc/kubernetes/ root@192.168.65.133:/etc/kubernetes/
scp /usr/lib/systemd/system/kube* root@192.168.65.133:/usr/lib/systemd/system

#删除无用的文件
rm -rf /etc/kubernetes/cfg/kubelet.kubeconfig 
rm -rf /etc/kubernetes/ssl/kubelet*
rm -rf /etc/kubernetes/logs/*

#修改配置文件
vi /etc/kubernetes/cfg/kubelet.conf
--hostname-override=node1
vi /etc/kubernetes/cfg/kube-proxy-config.yml
hostnameOverride: node1

#设置守护进程
systemctl daemon-reload & systemctl start kubelet kube-proxy & systemctl enable kubelet kube-proxy
systemctl status kubelet kube-proxy  #查看状态

#在master1服务器上执行查看新的证书申请
kubectl get csr     #查看node1证书申请
kubectl certificate approve    name    #name为上面命令所返回的申请name

kubectl get nodes    #执行后发现多出node1节点



#此时，加入node1节点成功，node2可使用同样方法加入，更多worker节点也是一样的

```





