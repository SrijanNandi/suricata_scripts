#!/bin/bash

#
### Proceed only when there is Internet Connectivity ###
#
if ping -q -c 1 -W 1 google.com >/dev/null; then
else
  echo "Please check internet connectivity"
  exit 1
fi

#
### Check kernel version ###
#
ver_kernel=`uname -a | awk '{print $(3)}' | cut -c1-4`
ver_kernel_num=4.19
if [ "$ver_kernel" == "$ver_kernel_num" ]; then
  echo "kernel version - 4.19  is already installed........[OK]"
else
  cd /tmp/
  wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-headers-4.19.0-041900_4.19.0-041900.201810221809_all.deb 
  wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-headers-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb
  wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-image-unsigned-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb 
  wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-modules-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb
  dpkg -i *.deb
  cd `pwd`
  shutdown -r now
fi

#
### Update and Upgrade ###
#
apt-get update && apt-get upgrade -y && apt-get autoremove -y && apt-get autoclean

#
### Check gcc ###
#
gcc -v >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "gcc installed........[OK]"
else
    echo -ne "Installing gcc\r"
    while true;do echo -n .;sleep 1;done &
    apt-get -y install build-essential make >/dev/null 2>&1
    kill $!; trap 'kill $!' SIGTERM
    echo Done
fi

#
### Check pkg-config ###
#
pkg-config --version >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "pkg-config installed........[OK]"
else
    echo -ne "Installing pkg-config\r"
    while true;do echo -n .;sleep 1;done &
    apt-get -y install pkg-config >/dev/null 2>&1
    kill $!; trap 'kill $!' SIGTERM
    echo Done
fi

#
### Check unzip ###
#
/usr/bin/unzip -v >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "unzip installed........[OK]"
else
    echo -ne "Installing unzip\r"
    while true;do echo -n .;sleep 1;done &
    apt-get -y install unzip >/dev/null 2>&1
    kill $!; trap 'kill $!' SIGTERM
    echo Done
fi

#
### Check set_irq_affinity script ###
#
if [ -x /usr/bin/set_irq_affinity_bynode.sh ]; then
    echo "NIC IRQ Script is installed........[OK]"
else
    echo -ne "Installing NIC IRQ Script\r"
    while true;do echo -n .;sleep 1;done &
    cd /tmp
    git clone -b master https://github.com/SrijanNandi/suricata_scripts.git >/dev/null 2>&1
    cd suricata_scripts/
    cp set_irq_affinity.sh /usr/sbin/ >/dev/null 2>&1
    cp set_irq_affinity_bynode.sh /usr/sbin/ >/dev/null 2>&1
    cp common_irq_affinity.sh /usr/sbin/ >/dev/null 2>&1
    chmod 755 /usr/sbin/set_irq_affinity.sh >/dev/null 2>&1
    chmod 755 /usr/sbin/set_irq_affinity_bynode.sh >/dev/null 2>&1
    chmod 755 /usr/sbin/common_irq_affinity.sh >/dev/null 2>&1
    cd `pwd`
    rm -rf /tmp/suricata_scripts >/dev/null 2>&1
    kill $!; trap 'kill $!' SIGTERM
    echo Done
fi

#
### Export Settings ###
#
PKG_CONFIG_PATH=/lib/pkgconfig
export PKG_CONFIG_PATH

#
### Change sshd_config with Port2224 ###
#
#sed -i 's/#Port 22/Port 2224/' /etc/ssh/sshd_config
#sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config

## Restart sshd for changes to take effect
#systemctl restart ssh >/dev/null 2>&1

#
### Install cmake and ragel for Hyperscan ###
#

which cmake >/dev/null 2>&1
if [ $? -ne 0 ]; then
    apt-get -y install cmake >/dev/null 2>&1
fi

which ragel >/dev/null 2>&1
if [ $? -ne 0 ]; then
    apt-get -y install ragel >/dev/null 2>&1
fi

#
### Check libboost ###
#
ver_libboost=`dpkg -s libboost-dev | grep 'Version' | awk '{print $2}'`
ver_libboost_num=1.65.1.0ubuntu1

if [ "$ver_libboost" == "$ver_libboost_num" ]; then
    echo "libboost is already installed........[OK]"
else
    echo -ne "Installing libboost\n"
    while true;do echo -n .;sleep 1;done &
    apt-get -y install libboost-dev >/dev/null 2>&1
    kill $!; trap 'kill $!' SIGTERM
fi

which git >/dev/null 2>&1
if [ $? -ne 0 ]; then
    apt-get -y install git >/dev/null 2>&1
fi

#
### Check PCRE, Suricata Dependencies and Hyperscan ###
#
ver_pcre=`pcretest -C | head -n 1 | awk '{print $3}'`
ver_pcre_num=8.41
if [ "$ver_pcre" == "$ver_pcre_num" ]; then
  echo "PCRE - 8.41 is already installed........[OK]"
else
  while true;do echo -n .;sleep 1;done &
  cd /tmp
  apt-get install -y libreadline-dev 
  apt-get install -y zlib1g-dev
  apt-get install -y libbz2-1.0 libbz2-dev libbz2-ocaml libbz2-ocaml-dev
  wget https://downloads.sourceforge.net/pcre/pcre-8.41.tar.bz2
  tar jxvf pcre-8.41.tar.bz2
  cd pcre-8.41
  ./configure --prefix=/usr \
          --docdir=/usr/share/doc/pcre-8.41 \
          --enable-unicode-properties \
          --enable-pcre16 \
          --enable-pcre32 \
          --enable-pcregrep-libz \
          --enable-pcregrep-libbz2 \
          --enable-pcretest-libreadline \
          --disable-static && make && make install
  mv -v /usr/lib/libpcre.so.* /lib &&
  ln -sfv ../../lib/$(readlink /usr/lib/libpcre.so) /usr/lib/libpcre.so
  cp pcre.h /usr/include/
  cd `pwd`
  apt-get -y install build-essential libpcap-dev   \
             libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev \
             libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev        \
             libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev autoconf automake \
             libtool libjansson4 libnspr4-dev libtcmalloc-minimal4 python-yaml libelf-dev rustc cargo \
             liblzma-dev liblz4-dev libmaxminddb-dev libluajit-5.1-dev g++-multilib
kill $!; trap 'kill $!' SIGTERM
echo Done
fi
    
ver_hyperscan=`ldconfig -v 2> /dev/null | grep libhs | tail -n 1 | awk '{print $(1)}'`
if [ "$ver_hyperscan" == "libhs_runtime.so.5" ]; then
  echo "hyperscan is installed........[OK]"
else
  cd /tmp
  apt-get install -y libpcap-dev
  apt-get download libsqlite3-0:amd64
  dpkg --force-depends --purge libsqlite3-0:amd64
  dpkg --install libsqlite3-0*amd64.deb
  apt-get install -y sqlite3=3.27.2-3~bpo9+1 libsqlite3-dev=3.27.2-3~bpo9+1
  git clone https://github.com/01org/hyperscan
  echo -ne "Installing hyperscan"
  while true;do echo -n .;sleep 1;done &
  cd /tmp/hyperscan && export PKG_CONFIG_PATH=/lib/pkgconfig && mkdir build && cd build  && cmake -DBUILD_STATIC_AND_SHARED=1 ../ && make -j 4 && make install
  kill $!; trap 'kill $!' SIGTERM
  cd `pwd`
  rm -rf /tmp/hyperscan*
  echo Done          
fi

## Check clang
ver_clang=`clang-3.9 --version | head -n 1| awk '{print $(3)}' | cut -c1-3`
ver_clang_num=3.9

if [ "$ver_clang" == "$ver_clang_num" ]; then
  echo "clang - 3.9 is already installed........[OK]"
else
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
  apt-get install -y software-properties-common
  apt-add-repository "deb https://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main"
  apt-get install -y apt-transport-https
  apt -o Acquire::AllowInsecureRepositories=true update
  apt-get install -y clang-3.9 lldb-3.9
fi

#
### Install libbpf ###
##
cd /tmp
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src/
make && make install
make install_headers
ldconfig
cd `pwd`
rm -rf /tmp/libbpf*
if grep -FR "/usr/lib64" /etc/ld.so.conf.d
then
    true
else
    echo "/usr/lib64" >> /etc/ld.so.conf.d/x86_64-linux-gnu.conf
fi
ldconfig

#
### Check Suricata ###
#
ver_suricata=`suricata -v | head -n 1 | awk '{print $(2)}' | cut -c1-5`
ver_suricata_num=5.0.0

if [ "$ver_suricata" == "$ver_suricata_num" ]; then
  echo "suricata version 5.0.0 is already installed........[OK]"
    cd /tmp
    wget --help | grep -q '\--show-progress' && _PROGRESS_OPT="-q --show-progress" || _PROGRESS_OPT=""
    wget https://www.openinfosecfoundation.org/download/suricata-5.0.0.tar.gz
    tar zxvf suricata-5.0.0.tar.gz
    cd suricata-5.0.0
 
    echo -ne "Installing suricata-latest"
    while true;do echo -n .;sleep 1;done &
    cargo install cargo-vendor
    CC=clang-3.9 ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib/ --enable-af-packet --enable-gccprotect --enable-geoip --enable-luajit --enable-hiredis --enable-rust --enable-ebpf --enable-ebpf-build && make clean && make -j 4 && make install && make install-full && ldconfig
    mkdir /etc/suricata/ebpf
    cp -r ebpf/*.bpf /etc/suricata/ebpf/
    kill $!; trap 'kill $!' SIGTERM
    cd `pwd`
    echo Done
else
  cd /tmp
    wget --help | grep -q '\--show-progress' && _PROGRESS_OPT="-q --show-progress" || _PROGRESS_OPT=""
    git clone  https://github.com/OISF/suricata.git
    cd suricata && git clone https://github.com/OISF/libhtp.git -b 0.5.x
    ./autogen.sh
 
    echo -ne "Installing suricata-latest"
    while true;do echo -n .;sleep 1;done &
    cargo install cargo-vendor
    CC=clang-3.9 ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib/ --enable-af-packet --enable-gccprotect --enable-debug --enable-geoip --enable-luajit --enable-hiredis --enable-rust --enable-ebpf --enable-ebpf-build && make clean && make -j 4 && make install && make install-full && ldconfig
    mkdir /etc/suricata/ebpf
    cp -r ebpf/*.bpf /etc/suricata/ebpf/
    kill $!; trap 'kill $!' SIGTERM
    cd `pwd`
    echo Done
fi

#
## Customizing suricata ##
#
SURICATA_CONF_FILE="/etc/suricata/suricata.yaml"
INT_NAME=`ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | sort | uniq -D -w6`
INT_COUNT=`ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | sort | uniq -D -w6 | wc -l`

declare -a array=($(echo "$INT_NAME" | tr ' ' '\n'))

ITER=1
THREADS_COUNT=$((40/$INT_COUNT))
for ((i=0; i<${#array[@]}; i+=2)); do
   TMP_FILE="/tmp/suricata.temp$i"
   cat << 'EOF' > $TMP_FILE
  - interface: FIRST_INT
    threads: THREADS_COUNT
    cluster-id: FIRST_ID
    defrag: no
    cluster-type: cluster_flow
    xdp-mode: driver
    xdp-filter-file:  /etc/suricata/ebpf/xdp_filter.bpf
    bypass: yes
    copy-mode: ips
    use-mmap: yes
    ring-size: 500000
    buffer-size: 5368709120
    rollover: no
    use-emergency-flush: yes
    copy-iface: SECOND_INT
  - interface: SECOND_INT
    threads: THREADS_COUNT
    cluster-id: SECOND_ID
    defrag: no
    cluster-type: cluster_flow
    xdp-mode: driver
    xdp-filter-file:  /etc/suricata/ebpf/xdp_filter.bpf
    bypass: yes
    copy-mode: ips
    use-mmap: yes
    ring-size: 500000
    buffer-size: 5368709120
    rollover: no
    use-emergency-flush: yes
    copy-iface: FIRST_INT
EOF
   sed -i "s/- interface: FIRST_INT/- interface: ${array[$i]}/g" $TMP_FILE
   sed -i "s/cluster-id: FIRST_ID/cuslter-id: $(expr 99 - $ITER)/g" $TMP_FILE
   sed -i "s/copy-iface: SECOND_INT/copy-iface: "${array[$i+1]}"/g" $TMP_FILE
   sed -i "s/- interface: SECOND_INT/- interface: "${array[$i+1]}"/g" $TMP_FILE
   sed -i "s/cluster-id: SECOND_ID/cuslter-id: $(expr 99 - $ITER - 1)/g" $TMP_FILE
   sed -i "s/copy-iface: FIRST_INT/copy-iface: "${array[$i]}"/g" $TMP_FILE 
   sed -i "s/threads: THREADS_COUNT/threads: $THREADS_COUNT/g" $TMP_FILE
   ITER=$(expr $ITER + 2)

done

cat /tmp/suricata.temp* >> /tmp/newfile.temp


if [ -f $SURICATA_CONF_FILE ]; then
   cp -r /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.ORIG
   cat << 'EOF' > $SURICATA_CONF_FILE
%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

    EXTERNAL_NET: "any"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21

default-log-dir: /var/log/suricata/

# global stats configuration
stats:
  enabled: yes
  interval: 8
  #decoder-events: true
  decoder-events-prefix: "decoder.event"
  #stream-events: flase

outputs:
  - stats:
      enabled: yes
      filename: stats.log
      append: no       # append to file (yes) or overwrite it (no)
      totals: yes       # stats for all threads merged together
      threads: no       # per thread stats

logging:
  default-log-level: notice
  default-output-filter:
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log

# Linux high speed capture support
af-packet:
AF_PACKET

## Step 5: App Layer Protocol Configuration

app-layer:
  protocols:
    krb5:
      enabled: yes
    ikev2:
      enabled: yes
    tls:
      enabled: yes
      detection-ports:
        dp: 443
      ja3-fingerprints: no
      encryption-handling: default

    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
      memcap: 2048mb
    ssh:
      enabled: yes
    smtp:
      enabled: yes
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
      # Configure inspected-tracker for file_data keyword
      inspected-tracker:
        content-limit: 100000
        content-inspect-min-size: 32768
        content-inspect-window: 4096
    imap:
      enabled: detection-only
    msn:
      enabled: detection-only
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
      #stream-depth: 0
    nfs:
      enabled: yes
    tftp:
      enabled: yes
    dns:
      global-memcap: 2048mb
      #state-memcap: 512kb
      #request-flood: 500
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes
      memcap: 4gb
      libhtp:
         default-config:
           personality: IDS
           request-body-limit: 200kb
           response-body-limit: 200kb
           request-body-minimal-inspect-size: 32kb
           request-body-inspect-window: 4kb
           response-body-minimal-inspect-size: 40kb
           response-body-inspect-window: 16kb
           response-body-decompress-layer-limit: 2
           http-body-inline: auto
           swf-decompression:
             enabled: yes
             type: both
             compress-depth: 0
             decompress-depth: 0
           double-decode-path: no
           double-decode-query: no

         server-config:
    modbus:
      enabled: no
      detection-ports:
        dp: 502
      stream-depth: 0

    # DNP3
    dnp3:
      enabled: no
      detection-ports:
        dp: 20000

    # Note: parser depends on Rust support
    ntp:
      enabled: yes

    dhcp:
      enabled: yes

# Limit for the maximum number of asn1 frames to decode (default 256)
asn1-max-frames: 256

## Advanced settings below

coredump:
  max-dump: unlimited
host-mode: auto
#max-pending-packets: 1024
max-pending-packets: 65534
runmode: workers
#default-packet-size: 1514
unix-command:
  enabled: auto

legacy:
  uricontent: enabled

action-order:
  - pass
  - drop
  - reject
  - alert


engine-analysis:
  rules-fast-pattern: yes
  rules: yes

#recursion and match limits for PCRE where supported
pcre:
  match-limit: 3500
  match-limit-recursion: 1500


host-os-policy:
  windows: []
  bsd: []
  bsd-right: []
  old-linux: []
  linux: [0.0.0.0/0]
  old-solaris: []
  solaris: []
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []

# Defrag settings:

defrag:
  memcap: 4gb
  hash-size: 65536
  trackers: 65535 # number of defragmented flows to follow
  max-frags: 1000000 # number of fragments to keep (higher than trackers)
  prealloc: yes
  timeout: 10

flow:
  memcap: 4gb
  hash-size: 131072
  prealloc: 1000000
  emergency-recovery: 20
  prune-flows: 5
  managers: 2  # default to one flow manager
  recyclers: 2 # default to one flow recycler thread
vlan:
  use-for-tracking: false

flow-timeouts:
  default:
    new: 5 #10
    established: 10 #100
    closed: 0
    bypassed: 5 #50
    emergency-new: 1 #5
    emergency-established: 2 #50
    emergency-closed: 0
    emergency-bypassed: 5
  tcp:
    new: 5 #10
    established: 10 #100
    closed: 5 #5
    bypassed: 5 #50
    emergency-new: 1
    emergency-established: 2 #50
    emergency-closed: 0 #5
    emergency-bypassed: 5
  udp:
    new: 5 #10
    established: 5 #100
    bypassed: 5 #50
    emergency-new: 1
    emergency-established: 1 #50
    emergency-bypassed: 5
  icmp:
    new: 5 #10
    established: 5 #100
    bypassed: 5 #50
    emergency-new: 1
    emergency-established: 1 #50
    emergency-bypassed: 5
    
stream:
  memcap: 4gb
  checksum-validation: no      # reject wrong csums
  inline: no
  prealloc-session: 1000000
  bypass: yes
  midstream: false
  async-oneside: false
  reassembly:
    memcap: 6gb
    depth: 1mb                  # reassemble 1mb into a stream
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

host:
  hash-size: 4096
  prealloc: 100000
  memcap: 1024mb

# Decoder settings

decoder:
  teredo:
    enabled: true

detect:
  profile: custom
  custom-values:
    toclient-groups: 300
    toserver-groups: 300
    toclient-sp-groups: 300
    toclient-dp-groups: 300
    toserver-src-groups: 300
    toserver-dst-groups: 5400
    toserver-sp-groups: 300
    toserver-dp-groups: 350
  sgh-mpm-context: full
  inspection-recursion-limit: 3000

  prefilter:
    default: mpm

  grouping:
    #tcp-whitelist: 53, 80, 139, 443, 445, 1433, 3306, 3389, 6666, 6667, 8080
    #udp-whitelist: 53, 135, 5060

  profiling:
    #inspect-logging-threshold: 200
    grouping:
      dump-to-disk: false
      include-rules: false      # very verbose
      include-mpm-stats: false

mpm-algo: hs

spm-algo: hs

threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 2,3,4,42,43,44,45 ]  # include only these CPUs in affinity settings
        mode: "balanced"
        prio:
          default: "high"
    - worker-cpu-set:
        cpu: [ "20-39","60-79" ]
        mode: "exclusive"
        prio:
          default: "high"

  detect-thread-ratio: 1.0

luajit:
  states: 128

default-rule-path: /etc/suricata/rules
rule-files:
 - custom.rules
 - emerging-activex.rules
 - emerging-attack_response.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
threshold-file: /etc/suricata/threshold.config
EOF

sed -i "/AF_PACKET/ e cat /tmp/newfile.temp" $SURICATA_CONF_FILE
sed -i '/AF_PACKET/d' $SURICATA_CONF_FILE
if [ $THREADS_COUNT == 6 ]; then
  echo $THREADS_COUNT
  sed -i "s/cpu\: \[ \"20-39\"\,\"60-79\" \]/cpu: [ \"22-39\",\"62-79\" ]/g" $SURICATA_CONF_FILE
fi

fi

rm -rf /tmp/suricata.temp*
rm -rf /tmp/newfile.temp*

#
## Creating the suricata init script ##
#
INIT_FILE="/etc/init.d/suricata"
if [ -f "$INIT_FILE" ]; then
  rm -rf $INIT_FILE
  cat << 'EOF' > $INIT_FILE
#!/bin/sh -e
#
### BEGIN INIT INFO
# Provides:          suricata
# Required-Start:    $time $network $local_fs $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Next Generation IDS/IPS
# Description:       Intrusion detection system that will
#                    capture traffic from the network cards and will
#                    match against a set of known attacks.
### END INIT INFO

. /lib/lsb/init-functions

# We'll add up all the options above and use them
NAME=suricata
DAEMON=/usr/bin/$NAME

check_root()  {
    if [ "$(id -u)" != "0" ]; then
        log_failure_msg "You must be root to start, stop or restart $NAME."
        exit 4
    fi
}

check_run_dir() {
    if [ ! -d /var/run/suricata ]; then
    mkdir /var/run/suricata
    chmod 0755 /var/run/suricata
    fi
}

check_root

SURCONF=/etc/suricata/suricata.yaml
PIDFILE="/var/run/suricata.pid"
SURICATA_OPTIONS=" -c $SURCONF --af-packet --pidfile $PIDFILE -D"

# See how we were called.
case "$1" in
  start)
       if [ -f $PIDFILE ]; then
           PID1=`cat $PIDFILE`
           if kill -0 "$PID1" 2>/dev/null; then
               echo "$NAME is already running with PID $PID1"
               exit 0
           fi
       fi
       check_run_dir
       echo -n "Starting suricata in IPS mode..."
       if [ -f /usr/lib/libtcmalloc_minimal.so.0 ] && [ "x$TCMALLOC" = "xYES" ]; then
           export LD_PRELOAD="/usr/lib/libtcmalloc_minimal.so.0"
       fi
       $DAEMON $SURICATA_OPTIONS > /var/log/suricata/suricata.log  2>&1 &
       echo " done."
       ;;
  stop)
       echo -n "Stopping suricata: "
       if [ -f $PIDFILE ]; then
           PID2=`cat $PIDFILE`
       else
           echo " No PID file found; not running?"
           exit 0;
       fi
       start-stop-daemon --oknodo --stop --quiet --pidfile=$PIDFILE --exec $DAEMON
       if [ -n "$PID2" ]; then
           kill "$PID2"
           ret=$?
           sleep 2
           if kill -0 "$PID2" 2>/dev/null; then
               ret=$?
               echo -n "Waiting . "
               cnt=0
               while kill -0 "$PID2" 2>/dev/null; do
                   ret=$?
                   cnt=`expr "$cnt" + 1`
                   if [ "$cnt" -gt 10 ]; then
                      kill -9 "$PID2"
                      break
                   fi
                   sleep 2
                   echo -n ". "
               done
           fi
       fi
       if [ -e $PIDFILE ]; then
           rm -f $PIDFILE > /dev/null 2>&1
       fi
       echo " done."
    ;;
  status)
       # Check if running...
       if [ -s $PIDFILE ]; then
           PID3=`cat $PIDFILE`
           if kill -0 "$PID3" 2>/dev/null; then
               echo "$NAME is running with PID $PID3"
               exit 0
           else
               echo "PID file $PIDFILE exists, but process not running!"
           fi
       else
          echo "$NAME not running!"
       fi
    ;;
  restart)
        $0 stop
        $0 start
    ;;
  force-reload)
        $0 stop
        $0 start
    ;;
  *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
esac

exit 0
EOF

else
  cat << 'EOF' > $INIT_FILE
#!/bin/sh -e
#
### BEGIN INIT INFO
# Provides:          suricata
# Required-Start:    $time $network $local_fs $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Next Generation IDS/IPS
# Description:       Intrusion detection system that will
#                    capture traffic from the network cards and will
#                    match against a set of known attacks.
### END INIT INFO

. /lib/lsb/init-functions

# We'll add up all the options above and use them
NAME=suricata
DAEMON=/usr/bin/$NAME

check_root()  {
    if [ "$(id -u)" != "0" ]; then
        log_failure_msg "You must be root to start, stop or restart $NAME."
        exit 4
    fi
}

check_run_dir() {
    if [ ! -d /var/run/suricata ]; then
    mkdir /var/run/suricata
    chmod 0755 /var/run/suricata
    fi
}

check_root

SURCONF=/etc/suricata/suricata.yaml
PIDFILE="/var/run/suricata.pid"
SURICATA_OPTIONS=" -c $SURCONF --af-packet --pidfile $PIDFILE -D"

# See how we were called.
case "$1" in
  start)
       if [ -f $PIDFILE ]; then
           PID1=`cat $PIDFILE`
           if kill -0 "$PID1" 2>/dev/null; then
               echo "$NAME is already running with PID $PID1"
               exit 0
           fi
       fi
       check_run_dir
       echo -n "Starting suricata in IPS mode..."
       if [ -f /usr/lib/libtcmalloc_minimal.so.0 ] && [ "x$TCMALLOC" = "xYES" ]; then
           export LD_PRELOAD="/usr/lib/libtcmalloc_minimal.so.0"
       fi
       $DAEMON $SURICATA_OPTIONS > /var/log/suricata/suricata.log  2>&1 &
       echo " done."
       ;;
  stop)
       echo -n "Stopping suricata: "
       if [ -f $PIDFILE ]; then
           PID2=`cat $PIDFILE`
       else
           echo " No PID file found; not running?"
           exit 0;
       fi
       start-stop-daemon --oknodo --stop --quiet --pidfile=$PIDFILE --exec $DAEMON
       if [ -n "$PID2" ]; then
           kill "$PID2"
           ret=$?
           sleep 2
           if kill -0 "$PID2" 2>/dev/null; then
               ret=$?
               echo -n "Waiting . "
               cnt=0
               while kill -0 "$PID2" 2>/dev/null; do
                   ret=$?
                   cnt=`expr "$cnt" + 1`
                   if [ "$cnt" -gt 10 ]; then
                      kill -9 "$PID2"
                      break
                   fi
                   sleep 2
                   echo -n ". "
               done
           fi
       fi
       if [ -e $PIDFILE ]; then
           rm -f $PIDFILE > /dev/null 2>&1
       fi
       echo " done."
    ;;
  status)
       # Check if running...
       if [ -s $PIDFILE ]; then
           PID3=`cat $PIDFILE`
           if kill -0 "$PID3" 2>/dev/null; then
               echo "$NAME is running with PID $PID3"
               exit 0
           else
               echo "PID file $PIDFILE exists, but process not running!"
           fi
       else
          echo "$NAME not running!"
       fi
    ;;
  restart)
        $0 stop
        $0 start
    ;;
  force-reload)
        $0 stop
        $0 start
    ;;
  *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
esac

exit 0
EOF

fi

chmod 755 /etc/init.d/suricata
update-rc.d suricata defaults

#
### Download Emerging Threats Ruleset ###
#
cd /etc/suricata
wget https://rules.emergingthreats.net/open/suricata-5.0.0/emerging.rules.tar.gz
tar zxvf emerging.rules.tar.gz
rm -rf emerging.rules.tar.gz
cd `pwd`

#
### Restarting Suricata ###
systemctl restart suricata

#
### Remove iptables ###
#
apt-get -y remove --purge iptables

#
### CPU Frequency tuning ###
#
CPU_FREQ_FILE=/etc/default/cpufrequtils


if [ -f "$CPU_FREQ_FILE" ]; then
    echo "cpufrequtils file exists..............[OK]"
else
    apt install linux-tools-common
    cpupower frequency-set -g performance
    apt-get install -y cpufrequtils
    echo "GOVERNOR=\"performance\"" > $CPU_FREQ_FILE
fi
for (( i = 0; i <=79; i++ )); do
        echo performance > /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor
done
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

#
### Disable C-States ###
#
GRUB_FILE=/etc/default/grub

if grep "intel_idle.max_cstate=0 processor.max_cstate=1" $GRUB_FILE; then
     echo "C-States already disabled in GRUB............[OK]"
else
     sed -i -e 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="intel_idle.max_cstate=0 processor.max_cstate=1"/g' $GRUB_FILE
fi
