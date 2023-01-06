if "%1"=="/copy" (
  py tools/windows/build_test.py --copy True
) else (
  py tools/windows/build_test.py
)
