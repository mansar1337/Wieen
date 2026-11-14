-- The probe of the agent: it asks a Luau VM of the client who it is.
-- The client has the VM of its own app (the DataModel is named "LuaApp",
-- it draws the menu and the avatar preview) and the VM of the experience
-- the player is in.  The name tells them apart without any capability:
-- reading `Name` of the DataModel is allowed to every thread.
--
-- The script stays simple on purpose: the bytecode of the client is
-- translated by the host compiler, and a few shapes of it do not survive
-- the translation.  One property read and one return do.
return game.Name
