# blktrace_with_process-Trace
Modified blktrace to trace process information together

```
   sudo ./blktrace -d /dev/sda -o- | ./blkparse -i- -a issue -f "%5T.%9t,%p,%C,%a,%3d,%S,%N,%J\n" -o dump_file
```
