from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
"""
class jwtBearer(HTTPBearer):
    def __init(self, auto_Error :bool = True):
        super(jwtBearer, self).__init__(auto_error = auto_Error)
    async def __call__(self, request = Request):
        credentials = HTTPAuthorizationCredentials = await super(jwtBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme """