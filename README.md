Commands to set up and run project

## Create .venv

```
python -m venv .venv
```

To active:

## Powershell

```
.\.venv\Scripts\Activate.ps1
```

## Command Prompt

```
.venv\Scripts\activate.bat
```

## Update pip

```
python -m pip install --upgrade pip
```

## Installing FastAPI

```
pip install fastapi uvicorn
pip install slowapi
```

## Command to run FastAPI

```
uvicorn main:app --reload
```