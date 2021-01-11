# Python

## Encode /decode url format using cli

```text
alias urldecode='python -c "import sys, urllib as ul; \ print ul.unquote_plus(sys.argv[1])"'
alias urlencode='python -c "import sys, urllib as ul; \ print ul.quote_plus(sys.argv[1])"'
using => urlencode 'q werty=/;'
```

