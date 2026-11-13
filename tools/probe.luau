-- The probe of the agent: it asks a Luau VM of the client what it can see.
-- The VM of the game knows `game` and `workspace`, the other ones of the
-- client do not.  The answer decides which VM the agent uses.
--
-- The script stays simple on purpose: the bytecode of the client is
-- translated by the host compiler, and a few shapes of it do not survive
-- the translation.  Two names and one concatenation do.
return typeof(game) .. "/" .. typeof(workspace)
