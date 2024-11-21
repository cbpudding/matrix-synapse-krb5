# Copyright (c) 2024 Alexander Hill

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import krb5
import logging

from synapse.module_api import JsonDict, LoginResponse, ModuleApi
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class KerberosAuthProvider:
    def __init__(self, config: Any, account_handler: ModuleApi):
        self.api = account_handler
        self.config = config
    
    def get_supported_login_types(self) -> Dict[str, Tuple[str, ...]]:
        return {"m.login.password": ("password",)}

    async def check_auth(
        self,
        username: str,
        login_type: str,
        login_dict: JsonDict
    ) -> Optional[
        Tuple[
            str,
            Optional[str]
        ]
    ]:
        # TODO: Look into potentially using m.login.sso for working with
        #       Kerberos tickets directly. ~ahill
        if login_type != "m.login.password":
            return None

        password = login_dict["password"]
        if password is None:
            return None
        
        context = krb5.init_context()

        user_id = self.api.get_qualified_user_id(username)
        localpart = user_id.split(":")[0][1:]
        # TODO: Is it safe to simply pipe the username into C like this? ~ahill
        principal = krb5.parse_name_flags(context, localpart.encode())

        options = krb5.get_init_creds_opt_alloc(context)
        try:
            creds = krb5.get_init_creds_password(context, principal, options, password.encode())
        except krb5.Krb5Error:
            logger.info("Failed to authorize {user_id} via Kerberos")
            return None

        cache = krb5.cc_new_unique(context, b"MEMORY")
        krb5.cc_initialize(context, cache, principal)
        krb5.cc_store_cred(context, cache, creds)

        if (await self.api.check_user_exists(user_id)) is None:
            user_id = await self.api.register_user(localpart.lower())
            logger.info("User {user_id} registered via Kerberos")

        logger.info("Authorized {user_id} via Kerberos")
        return user_id