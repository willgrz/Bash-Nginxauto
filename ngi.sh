#/bin/bash
#William 10.2015

#echo help
if [ "$1" == "-h" ]; then
    echo "Usage:"
    echo "General:"
    echo "-WWW is added as sec domain"
    echo "localip4+6 is always required"
    echo "-HTTP will be redirected to HTTPS"
    echo "-CRT File may contain IM/Root certs"
    echo "-No cert file/key = no SSL/redir"
    echo "-Website is automatically added to Piwik"
    echo "-----------"
    echo "Reverse proxy setup"
    echo "-If you specify 80/8080 to backend SSL is disabled"
    echo "$0 rev domain localip4 localip6 sourceip4 backendport certfile keyfile"
    echo "$0 rev rdns.im 178.17.171.2 2a00:1dc0:cafe::c218:195 107.189.2.55 443 /etc/nginx/ssl/multi.crt /etc/nginx/multi.key"
    echo "-----------"
    echo "Static/HTML host"
    echo "$0 sta domain localip4 localip6 certfile keyfile"
    echo "$0 sta rdns.im 178.17.171.2 2a00:1dc0:cafe::c218:195 /etc/nginx/ssl/multi.crt /etc/nginx/multi.key"
    echo "-----------"
    echo "PHP enabled host"
    echo "-Uses PHP 5.4"
    echo "-Creates own FPM Pool"
    echo "-Defaults to 5 start servers, min spare 2, max spare 8, max children 10"
    echo "$0 php domain localip4 localip6 certfile keyfile"
    echo "$0 php rdns.im 178.17.171.2 2a00:1dc0:cafe::c218:195 /etc/nginx/ssl/multi.crt /etc/nginx/multi.key"
    echo "-----------"
    echo "PHP enabled host with MySQL"
    echo "-Uses PHP 5.4"
    echo "-Creates own FPM Pool"
    echo "-Defaults to 5 start servers, min spare 2, max spare 8, max children 10"
    echo "$0 phpm domain localip4 localip6 dbname certfile keyfile"
    echo "$0 phpm rdns.im 178.17.171.2 2a00:1dc0:cafe::c218:195 /etc/nginx/ssl/multi.crt /etc/nginx/multi.key"
    exit 0
fi

#check if root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 2>&1
    exit 1
fi

#config
#path for reverse proxy configs
revconf=/etc/nginx/conf.d/reverse/
#path for local configs
locconf=/etc/nginx/conf.d/local/
#php-fpm config dir
fpmconf=/etc/php5/fpm/pool.d/
#www dir
wwwd=/var/www/
#DNS 1 - Fusl VIE is 79.133.43.124
dns1=79.133.43.124 
#DNS 2 - Fusl BUC is 89.34.26.150
dns2=89.34.26.150
#nginx user and group
nuser=www-data
ngroup=www-data
#php-fpm user and group
puser=www-data
pgroup=www-data
#mysql root user file
mroot=/root/.my.cnf



################FUNCTIONS AND SHIT BRO
#this checks if domain is already existing on server
function check_existing {
    cdomain=$1
    if [ -f "$revconf/$cdomain.conf" ]; then
        echo "Error: $cdomain does already exist in $revconf as $cdomain.conf - Please remove it - exiting"
        exit 1
    elif [ -f "$locconf/$cdomain.conf" ]; then
        echo "Error: $cdomain does already exist in $locconf as $cdomain.conf - Please remove it - exiting"
        exit 1
    fi
}

#this fixes owner
function fix_perms {
    cdomain=$1
    if [ -f "$revconf/$cdomain.conf" ]; then
        chown $nuser:$ngroup $revconf/$cdomain.conf
    elif [ -f "$locconf/$cdomain.conf" ]; then
        chown $nuser:$ngroup $locconf/$cdomain.conf
    fi
}

#this runs some checks on input
function check_sanity {
    #functions in function
        #check if is valid IPv4
        function isipv4 {
            ipv4=$1
            #no easy way to check this
            echo "Check: IPv4 currently not verified - ok"
        }

        #check if is valid IPv6
        function isipv6 {
            ipv6=$1
            #currently i have not found a simple way to verify isipv6, so do nothing
            echo "Check: IPv6 currently not verified - ok"
        }

        #check if cert exists and is valid for given domain (as we use SNI we need to know that, else the server will display wrong pages, you could circumvent this with a dedicated IP but this aint my usage case)
        function iscrt {
            #oh hell naw, infunction
            function crt_valid {
                #check if crt matches key
                #this is currently empty as the nginx crt might contain CAs
                echo "Check: CRT+KEY match currently not verified - ok"
            }
            crt_valid
            #check if cert matches domain
            echo "Check: domain is in cert currently not verified - ok"
            #empty currently for same reason as crt_valid
        }

        #check if port is valid
        function isport {
            #also empty
            echo "Check: Port is currently not verified - ok"
        }
            
        

    #set what to check, if rev we need other checks
    if [ "$do" == "rev" ]; then
        #is rev, resort variables
        dom=$1
        cip4=$2
        cip6=$3
        cips=$4
        bep=$5
        crt=$6
        crtk=$7
    else
        #is host, set vars
        dom=$1
        cip4=$2
        cip6=$3
        crt=$5
        crtk=$5
    fi
    #run actual checks
    isipv4 $cip4
    if [ -n $cips ]; then
        isipv4 $cips
        #if this is set we can be sure it is rev, thus also run port check which is only set on rev call
        isport $bep
    fi
    if [ -n $crt ]; then
        iscrt $crt
    fi
    echo "Check: All variables ok - ok"
}

#this function echoes redir code into the target conf
function https_redir {
    conffile=$1
    echo '#HTTP to HTTPS redirect' >>$conffile
    echo 'server {' >>$conffile
    echo 'listen ABZ1:80;' >>$conffile
    echo 'listen [ABZ2]:80;' >>$conffile
    echo 'server_name DOMAIN www.DOMAIN;' >>$conffile
    echo 'return 301 https://$host$request_uri;' >>$conffile
    echo '}' >>$conffile
    rpl -q "ABZ1" "$localip4" $conffile >>/dev/null
    rpl -q "ABZ2" "$localip6" $conffile >>/dev/null
    rpl -q "DOMAIN" "$domain" $conffile >>/dev/null
    echo 'Done: HTTPS Redir set'
}


#this function creates a new reverse proxy config
function create_rev {
    dom=$1
    cip4=$2
    cip6=$3
    cips=$4
    bep=$5
    crt=$6
    crtk=$7
    #build SRCPASS target server depending on SSL set or not
    if [ "$bep" == "80" ] || [ "$bep" == "8080" ]; then
        #we have no SSL
        srcpass="http://$cips:$bep"
    else
        #we have SSL
        srcpass="https://$cips:$bep"
    fi
    #echo default conf into file
    cat << 'EOF' >> $revconf/$dom.conf
#SERVER FOR ZDOMAIN
server {
    #IFSSL listen ZTARGETIP4:443 ssl;
    #IFSSL listen [ZTARGETIP6]:443 ssl;
    #IFNOSSL listen ZTARGETIP4:80;
    #IFNOSSL listen [ZTARGETIP6]:80;
    server_name ZDOMAIN www.ZDOMAIN;
    #IFSSL ssl_certificate           ZSCERT;
    #IFSSL ssl_certificate_key       ZSKEY;
    #IFSSL ssl on;
    #IFSSL ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
    #IFSSL ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    #IFSSL ssl_prefer_server_ciphers on;
    #IFSSL ssl_session_cache shared:SSL:10m;
    #IFSSL add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
    #IFSSL add_header X-Frame-Options DENY;
    #IFSSL add_header X-Content-Type-Options nosniff;
    #IFSSL ssl_session_tickets off;
    #IFSSL resolver ZDNS1 ZDNS2 valid=300s;
    #IFSSL resolver_timeout 10s;
    access_log /var/log/nginx/reverse/ZDOMAIN.access.log;
    error_log /var/log/nginx/reverse/ZDOMAIN.error.log;
    location / {
      proxy_set_header        Host $host;
      proxy_set_header        X-Real-IP $remote_addr;
      proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto $scheme;
      proxy_pass SRCPASS;
      proxy_read_timeout  180;
    }
}
EOF
    #default rpls
    rpl -q "ZTARGETIP4" "$cip4" $revconf/$domain.conf 2>$1 >>/dev/null
    rpl -q "ZTARGETIP6" "$cip6" $revconf/$domain.conf 2>$1 >>/dev/null
    rpl -q "ZDOMAIN" "$dom" $revconf/$domain.conf 2>$1 >>/dev/null
    #SSL/noSSL rpls
    if [ -n "$crt" ]; then
        #have SSL, remove the commented SSL things
        rpl -q "#IFSSL" "" $revconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZSCERT" "$crt" $revconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZSKEY" "$crtk" $revconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZDNS1" "$dns1" $revconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZDNS2" "$dns2" $revconf/$domain.conf 2>$1 >>/dev/null
    else
        rpl -q "#IFNOSSL" "" $revconf/$domain.conf 2>$1 >>/dev/null
    fi
    #upstream srcpass
    rpl -q "SRCPASS" "$srcpass" $revconf/$domain.conf 2>$1 >>/dev/null
     #done
     echo "Done: Reverse Proxy for $domain set up on $cip4 / $cip6"
}

#this function creates a static HTTP host
function create_http {
    dom=$1
    cip4=$2
    cip6=$3
    crt=$4
    crtk=$5
    mkdir -p $wwwd/$dom
    chown -R $nuser:$ngroup $wwwd/$dom
    cat << 'EOF' >> $locconf/$dom.conf
#SERVER FOR ZDOMAIN
server {
    #IFSSL listen ZTARGETIP4:443 ssl;
    #IFSSL listen [ZTARGETIP6]:443 ssl;
    #IFNOSSL listen ZTARGETIP4:80;
    #IFNOSSL listen [ZTARGETIP6]:80;
    server_name ZDOMAIN www.ZDOMAIN;
    #IFSSL ssl_certificate           ZSCERT;
    #IFSSL ssl_certificate_key       ZSKEY;
    #IFSSL ssl on;
    #IFSSL ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
    #IFSSL ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    #IFSSL ssl_prefer_server_ciphers on;
    #IFSSL ssl_session_cache shared:SSL:10m;
    #IFSSL add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
    #IFSSL add_header X-Frame-Options DENY;
    #IFSSL add_header X-Content-Type-Options nosniff;
    #IFSSL ssl_session_tickets off;
    #IFSSL resolver ZDNS1 ZDNS2 valid=300s;
    #IFSSL resolver_timeout 10s;
    access_log /var/log/nginx/local/ZDOMAIN.access.log;
    error_log /var/log/nginx/local/ZDOMAIN.error.log;
    root WEBROOT/ZDOMAIN;
    #IFNOPHP index index.html index.htm;
    #IFPHP client_max_body_size 100M;
    #IFPHP location ~ \.php$ {
    #IFPHP     fastcgi_param PATH_TRANSLATED $document_root$fastcgi_script_name;
    #IFPHP     client_max_body_size 100M;
    #IFPHP     fastcgi_pass unix:/var/run/php5-fpm-ZDOMAIN.sock;
    #IFPHP     fastcgi_index index.php;
    #IFPHP     include fastcgi_params;
    #IFPHP }
    location ~ /\. {
        deny all;
    }
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
    #default rpls
    rpl -q "ZTARGETIP4" "$cip4" $locconf/$domain.conf 2>$1 >>/dev/null
    rpl -q "ZTARGETIP6" "$cip6" $locconf/$domain.conf 2>$1 >>/dev/null
    rpl -q "ZDOMAIN" "$dom" $locconf/$domain.conf 2>$1 >>/dev/null
    rpl -q "WEBROOT" "$wwwd" $locconf/$domain.conf 2>$1 >>/dev/null
    rpl -q "#IFNOPHP" "" $locconf/$domain.conf 2>$1 >>/dev/null
    #SSL/noSSL rpls
    if [ -n "$crt" ]; then
        #have SSL, remove the commented SSL things
        rpl -q "#IFSSL" "" $locconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZSCERT" "$crt" $locconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZSKEY" "$crtk" $locconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZDNS1" "$dns1" $locconf/$domain.conf 2>$1 >>/dev/null
        rpl -q "ZDNS2" "$dns2" $locconf/$domain.conf 2>$1 >>/dev/null
    else
        rpl -q "#IFNOSSL" "" $locconf/$domain.conf 2>$1 >>/dev/null
    fi
    echo "Done: Static host for $domain set up on $cip4 / $cip6 with WWW root $wwwd/$dom"
}


#enables PHP (create pool and enable in conf)
function enable_php {
    pdom=$1
    #enable PHP in nginx config
    rpl -q "#IFPHP" "" $locconf/$pdom.conf 2>$1 >>/dev/null
    #replace index
    rpl -q "index.html" "index.htm index.php" $locconf/$pdom.conf 2>$1 >>/dev/null
    #create pool
    cat << 'EOF' >> $fpmconf/$pdom.conf
[ZDOMAIN]
user = PUSER
group = PGROUP
listen = /var/run/php5-fpm-ZDOMAIN.sock
listen.owner = PUSER
listen.group = PGROUP
pm = dynamic
pm.max_children = 10
pm.start_servers = 5
pm.min_spare_servers = 2
pm.max_spare_servers = 8
chdir = /
php_admin_value[error_log] = /var/log/fpm-php.ZDOMAIN.log
php_admin_flag[log_errors] = on
EOF
    rpl -q "ZDOMAIN" "$pdom" $fpmconf/$pdom.conf 2>$1 >>/dev/null
    rpl -q "PUSER" "$puser" $fpmconf/$pdom.conf 2>$1 >>/dev/null
    rpl -q "PGROUP" "$pgroup" $fpmconf/$pdom.conf 2>$1 >>/dev/null
    /etc/init.d/php5-fpm restart $fpmconf/$pdom.conf
    echo "Done: PHP enabled for $pdom"
}

#creates a mysql DB
function create_mysql {
    mydom=$1
    rpass=$(cat $mroot | grep 'password=' | sed -e 's/password=//')
    upass=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w35 | head -n1)
    myuser=$(echo $mydom | sed -e 's/\.\+//g')
mysql -uroot -p$rpass<<MYSQL_SCRIPT
CREATE DATABASE $myuser;
CREATE USER '$myuser'@'localhost' IDENTIFIED BY '$upass';
GRANT ALL PRIVILEGES ON $myuser.* TO '$myuser'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT
echo "Done: MySQL user/DB created, password: $upass"
}

################//FUNCTIONS END BRO


#variables
do=$1

case $do in
rev)
    domain=$2
    localip4=$3
    localip6=$4
    sourceip4=$5
    backendport=$6
    certfile=$7
    keyfile=$8
    check_existing $domain
    check_sanity $domain $localip4 $localip6 $sourceip4 $backendport $certfile $keyfile
    if [ -n "$certfile" ]; then
        #we have SSL cert, so start with redir
        https_redir $revconf/$domain.conf
    fi
    create_rev $domain $localip4 $localip6 $sourceip4 $backendport $certfile $keyfile
    fix_perms $domain

;;
sta)
    domain=$2
    localip4=$3
    localip6=$4
    certfile=$5
    keyfile=$6
    check_existing $domain
    check_sanity $domain $localip4 $localip6 $certfile $keyfile
    if [ -n "$certfile" ]; then
        #we have SSL cert, so start with redir
        https_redir $locconf/$domain.conf
    fi
    create_http $domain $localip4 $localip6 $certfile $keyfile
;;
php)
    domain=$2
    localip4=$3
    localip6=$4
    certfile=$5
    keyfile=$6
    check_existing $domain
    check_sanity $domain $localip4 $localip6 $certfile $keyfile
    if [ -n "$certfile" ]; then
        #we have SSL cert, so start with redir
        https_redir $locconf/$domain.conf
    fi
    create_http $domain $localip4 $localip6 $certfile $keyfile
    enable_php $domain
;;
phpm)
    domain=$2
    localip4=$3
    localip6=$4
    certfile=$5
    keyfile=$6
    check_existing $domain
    check_sanity $domain $localip4 $localip6 $certfile $keyfile
    if [ -n "$certfile" ]; then
        #we have SSL cert, so start with redir
        https_redir $locconf/$domain.conf
    fi
    create_http $domain $localip4 $localip6 $certfile $keyfile
    enable_php $domain
    create_mysql $domain
;;
esac




