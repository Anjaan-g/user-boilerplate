from decouple import config

from .base import *

ENVIRONMENT = config('ENVIRONMENT')
if ENVIRONMENT=='LOCAL':
    from .local import *
elif ENVIRONMENT=='PROD':
    from .prod import *
else:
    print("Invalid Env")