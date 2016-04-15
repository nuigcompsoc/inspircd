/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2016 Douglas Temple <douglas@dtemple.info>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "users.h"
#include "channels.h"
#include "modules.h"

#include <security/pam_appl.h>

#ifdef _WIN32
#error Windows does not have PAM. You cannot use this!
#endif

/* $ModDesc: Allow/Deny connections based upon PAM response */
/* $LinkerFlags: -lpam */

class ModulePAMAuth : public Module
{
  LocalIntExt PAMAuthed;
  std::string service;
  //  bool verbose;
  //bool useusername;

  
public:
	ModulePAMAuth()
		: PAMAuthed("pamauth", this)
	{
	}

	void init()
	{
		ServerInstance->Modules->AddService(PAMAuthed);
		Implementation eventlist[] = { I_OnCheckReady, I_OnRehash, I_OnUserRegister };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
		OnRehash(NULL);
	}

	~ModulePAMAuth()
	{
	  // Deliberately empty. PAM contexts are freed after each inquiry
	}

	void OnRehash(User* user)
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("pamauth");

		service			= tag->getString("service");
		//		verbose			= tag->getBool("verbose");		/* Set to true if failed connects should be reported to operators */
		//		useusername		= tag->getBool("userfield");

	}

	ModResult OnUserRegister(LocalUser* user)
	{
		if (!CheckCredentials(user))
		{
			ServerInstance->Users->QuitUser(user, "Access Denied");
			return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}
  
	bool CheckCredentials(LocalUser* user)
	{
	  static struct pam_conv conv = { NULL, NULL };
	  pam_handle_t *pamh = NULL;
	  int pamstart;
	  int pampass;
	  int pamauth;
	  int pamret;
	  int accessret = PAM_AUTH_ERR;

	  pamstart = pam_start(service.c_str(),user->ident.c_str(),&conv,&pamh);

	  if( pamstart != PAM_SUCCESS )
	    {
	      ServerInstance->SNO->WriteToSnoMask('c',"Error: PAM failed to initialize");
	      return false;
	    }

	  if( user->password.empty())
	    {
	      ServerInstance->SNO->WriteToSnoMask('c',"Forbidden connection from %s (no password provided)", user->GetFullRealHost().c_str());
	      return false;
	    }
	  
	  pampass = pam_set_item( pamh, PAM_AUTHTOK, user->password.c_str() );

	  if( pampass != PAM_SUCCESS )
	    {
	      ServerInstance->SNO->WriteToSnoMask('c',"Error: PAM password failed. Error code %d", pampass);
	      return false;
	    }

	  pamauth = pam_authenticate( pamh, PAM_DISALLOW_NULL_AUTHTOK );

	  if( pamauth == PAM_SUCCESS )
	    {
	      accessret = pam_acct_mgmt(pamh, 0);
	    }
	  else
	    {
	      const char *errstr = pam_strerror(pamh, pamauth);
	      ServerInstance->SNO->WriteToSnoMask('c',"Error: PAM failure: %s", errstr);
	      return false;
	    }

	  if (accessret == PAM_SUCCESS)
	    {
	      return true;
	    }

	  switch(accessret){
	  case PAM_SUCCESS :
	    return true;
	    break;
	  default :
	    ServerInstance->SNO->WriteToSnoMask('c',"Error: Access denied for %s", user->ident.c_str());
	    return false;
	    break;
	  }		   

	  pamret = pam_end(pamh, accessret);

	  if(pamret != PAM_SUCCESS)
	    {
	      ServerInstance->SNO->WriteToSnoMask('c',"Error: PAM Free failure");
	      return false;
	    }
	      
	}

	ModResult OnCheckReady(LocalUser* user)
	{
		return PAMAuthed.get(user) ? MOD_RES_PASSTHRU : MOD_RES_DENY;
	}

	Version GetVersion()
	{
		return Version("Allow/Deny connections based upon response from PAM", VF_VENDOR);
	}

};

MODULE_INIT(ModulePAMAuth)
