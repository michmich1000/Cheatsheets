# Git

Push new commit

```bash
git checkout -b <branch_name>
git add .
git commit -m "My commit message"
git push origin <branch_name>

git add . && git commit -m "My commit message" && git push origin master
```

>you also can run `git add -p` to check diff step by step


Amend to last comit 

```bash
git add . && git commit --amend --no-edit && git push -f
```
