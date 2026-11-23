# Neuro-Wolf: עבודה על מחשבי ה-mesh

התיקייה הזאת מייצרת מסלולי כלים וסוכנים לאימון של Neuro-Wolf0.1. כל מחשב מקבל חלק אחר של ExeBench, כך שאין כפילויות.

## איזה מחשב מקבל איזה חלק
- המחשב הראשי: חלק 0 (כבר רץ).
- OhProggraming (Windows): חלק 1
- maor (Linux): חלק 2
- Mac mini: חלק 3

## הפעלה
1. להוריד את המאגר (פעם אחת; המאגר פרטי, צריך להיות מחובר ל-GitHub בחשבון ori-liloss):
   `git clone https://github.com/ori-liloss/neuro-wolf-worker.git`
   ואחר כך, כדי לקבל עדכונים: `git pull` בתוך התיקייה.
2. צריך Python 3 שמותקן במחשב (כבר יש בשלושתם, ה-mesh משתמש בו).
3. להריץ בתוך התיקייה `neuro-wolf-worker`:
   - Windows: `powershell -ExecutionPolicy Bypass -File .\run.ps1 -Share 1`
   - Linux: `bash run.sh 2`
   - Mac: `bash run.sh 3`

הסקריפט מוריד את Zig הרשמי (בודק את החתימה), מתקין את lief, capstone ו-transformers, ומפעיל שני תהליכים בעדיפות נמוכה.

## כשזה מסתיים
הקובץ `out/tools-share<N>.jsonl` מפסיק לגדול (או ב-`out/tools.log` מופיע `done`). להעתיק אותו למחשב הראשי, לתיקייה
`D:\neuro-models\wolf01\gen\tools\`. המחשב הראשי מוריד כפילויות ובודק כל שורה לפני האימון.

אפשר לעצור בכל רגע ולהריץ שוב: הוא ממשיך מאיפה שעצר.
