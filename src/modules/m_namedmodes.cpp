/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
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

static void DisplayList(LocalUser* user, Channel* channel)
{
	Numeric::ParamBuilder<1> numeric(user, 961);
	numeric.AddStatic(channel->name);

	const ModeParser::ModeHandlerMap& mhs = ServerInstance->Modes->GetModes(MODETYPE_CHANNEL);
	for (ModeParser::ModeHandlerMap::const_iterator i = mhs.begin(); i != mhs.end(); ++i)
	{
		ModeHandler* mh = i->second;
		if (!channel->IsModeSet(mh))
			continue;
		numeric.Add("+" + mh->name);
		if (mh->GetNumParams(true))
		{
			if ((mh->name == "key") && (!channel->HasUser(user)) && (!user->HasPrivPermission("channels/auspex")))
				numeric.Add("<key>");
			else
				numeric.Add(channel->GetModeParameter(mh));
		}
	}
	numeric.Flush();
	user->WriteNumeric(960, channel->name, "End of mode list");
}

class CommandProp : public SplitCommand
{
 public:
	CommandProp(Module* parent)
		: SplitCommand(parent, "PROP", 1)
	{
		syntax = "<user|channel> {[+-]<mode> [<value>]}*";
	}

	CmdResult HandleLocal(const std::vector<std::string>& parameters, LocalUser* src)
	{
		Channel* const chan = ServerInstance->FindChan(parameters[0]);
		if (!chan)
		{
			src->WriteNumeric(Numerics::NoSuchNick(parameters[0]));
			return CMD_FAILURE;
		}

		if (parameters.size() == 1)
		{
			DisplayList(src, chan);
			return CMD_SUCCESS;
		}
		unsigned int i = 1;
		Modes::ChangeList modes;
		while (i < parameters.size())
		{
			std::string prop = parameters[i++];
			if (prop.empty())
				continue;
			bool plus = prop[0] != '-';
			if (prop[0] == '+' || prop[0] == '-')
				prop.erase(prop.begin());

			ModeHandler* mh = ServerInstance->Modes->FindMode(prop, MODETYPE_CHANNEL);
			if (mh)
			{
				if (mh->GetNumParams(plus))
				{
					if (i != parameters.size())
						modes.push(mh, plus, parameters[i++]);
				}
				else
					modes.push(mh, plus);
			}
		}
		ServerInstance->Modes->ProcessSingle(src, chan, NULL, modes, ModeParser::MODE_CHECKACCESS);
		return CMD_SUCCESS;
	}
};

class DummyZ : public ModeHandler
{
 public:
	DummyZ(Module* parent) : ModeHandler(parent, "namebase", 'Z', PARAM_ALWAYS, MODETYPE_CHANNEL)
	{
		list = true;
	}

	// Handle /MODE #chan Z
	void DisplayList(User* user, Channel* chan)
	{
		if (IS_LOCAL(user))
			::DisplayList(static_cast<LocalUser*>(user), chan);
	}
};

class ModuleNamedModes : public Module
{
	CommandProp cmd;
	DummyZ dummyZ;
 public:
	ModuleNamedModes() : cmd(this), dummyZ(this)
	{
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides the ability to manipulate modes via long names.",VF_VENDOR);
	}

	void Prioritize()
	{
		ServerInstance->Modules->SetPriority(this, I_OnPreMode, PRIORITY_FIRST);
	}

	ModResult OnPreMode(User* source, User* dest, Channel* channel, Modes::ChangeList& modes) CXX11_OVERRIDE
	{
		if (!channel)
			return MOD_RES_PASSTHRU;

		Modes::ChangeList::List& list = modes.getlist();
		for (Modes::ChangeList::List::iterator i = list.begin(); i != list.end(); )
		{
			Modes::Change& curr = *i;
			// Replace all namebase (dummyZ) modes being changed with the actual
			// mode handler and parameter. The parameter format of the namebase mode is
			// <modename>[=<parameter>].
			if (curr.mh == &dummyZ)
			{
				std::string name = curr.param;
				std::string value;
				std::string::size_type eq = name.find('=');
				if (eq != std::string::npos)
				{
					value.assign(name, eq + 1, std::string::npos);
					name.erase(eq);
				}

				ModeHandler* mh = ServerInstance->Modes->FindMode(name, MODETYPE_CHANNEL);
				if (!mh)
				{
					// Mode handler not found
					i = list.erase(i);
					continue;
				}

				curr.param.clear();
				if (mh->GetNumParams(curr.adding))
				{
					if (value.empty())
					{
						// Mode needs a parameter but there wasn't one
						i = list.erase(i);
						continue;
					}

					// Change parameter to the text after the '='
					curr.param = value;
				}

				// Put the actual ModeHandler in place of the namebase handler
				curr.mh = mh;
			}

			++i;
		}

		return MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleNamedModes)
