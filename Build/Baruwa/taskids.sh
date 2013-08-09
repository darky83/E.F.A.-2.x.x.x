#!/bin/sh -xe

PATCH="
--- domains.py  2013-06-25 12:49:47.000000000 -0400
+++ domains.py  2013-06-25 13:26:18.169758564 -0400
@@ -476,6 +476,8 @@
                                     server.id,
                                     3])
             taskid = task.task_id
+            if not 'taskids' in session:
+                session['taskids'] = []
             session['taskids'].append(taskid)
             session['testdest-count'] = 1
             session.save()"
echo "$PATCH" | patch -p0
