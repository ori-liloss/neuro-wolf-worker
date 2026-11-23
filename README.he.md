# Neuro-Wolf: עבודה על מחשבי ה-mesh

התיקייה הזאת מייצרת מסלולי כלים וסוכנים לאימון של Neuro-Wolf0.1. כל מחשב מקבל חלק אחר של ExeBench, כך שאין כפילויות.

## איזה מחשב מקבל איזה חלק
- המחשב הראשי: חלק 0 (כבר רץ).
- OhProggraming (Windows): חלק 1
- maor (Linux): חלק 2
- Mac mini: חלק 3

## הפעלה: פקודה אחת, פעם אחת בכל מחשב
הפקודה מורידה את המאגר פעם אחת (לתיקייה `neuro-wolf-worker` בתיקיית הבית), מפעילה את העבודה עכשיו, וקובעת שהיא תופעל שוב לבד אחרי כל הפעלה מחדש של המחשב. בכל הפעלה היא עושה `git pull`, לא clone מחדש, ואם העבודה כבר רצה היא לא מפעילה אותה פעמיים.

- OhProggraming (Windows, ב-PowerShell):
  `irm https://raw.githubusercontent.com/ori-liloss/neuro-wolf-worker/main/install.ps1 -OutFile $env:TEMP
w-install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP
w-install.ps1 -Share 1`
- maor (Linux):
  `curl -fsSL https://raw.githubusercontent.com/ori-liloss/neuro-wolf-worker/main/install.sh | bash -s 2`
- Mac mini:
  `curl -fsSL https://raw.githubusercontent.com/ori-liloss/neuro-wolf-worker/main/install.sh | bash -s 3`

צריך git ו-Python 3 במחשב. הסקריפט מוריד את Zig הרשמי (בודק את החתימה), מתקין את lief, capstone ו-transformers, ומפעיל שני תהליכים בעדיפות נמוכה.

## כשזה מסתיים
הקובץ `out/tools-share<N>.jsonl` מפסיק לגדול (או ב-`out/tools.log` מופיע `done`). להעתיק אותו למחשב הראשי, לתיקייה
`D:\neuro-models\wolf01\gen\tools\`. המחשב הראשי מוריד כפילויות ובודק כל שורה לפני האימון.

אפשר לעצור בכל רגע ולהריץ שוב: הוא ממשיך מאיפה שעצר.
