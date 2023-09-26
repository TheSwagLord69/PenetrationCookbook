> A tool to dump a git repository from a website.


#Web_Application #Git

# Download

Download
```bash
git clone https://github.com/arthaud/git-dumper
```

Install requirements
```bash
cd git-dumper
pip install -r requirements.txt
```

# Usage

Usage to dump exposed web `git` repository
```bash
python git_dumper.py http://192.168.205.169/.git/ /home/kali/Desktop/test
```

View `git` log
```bash
cd /home/kali/Desktop/test/.git
git log
```

Show specific commits
```bash
git show 719fc24a317eb3454e6634e642517a9e8e3b5869
```