-- The greeting the agent shows when the player is in the experience.
--
-- Two channels, both of the client itself: the notification API of the
-- StarterGui (it draws the toast in the corner) and the developer console
-- of F9, which keeps everything printed as CreatorOutput.
--
-- The answer tells the agent whether the place is ready: "wait" asks for
-- another try, "ok" means the greeting is up.
--
-- Every statement is kept short: the compiler splits the script at
-- statement boundaries, and the loader of the client refuses a statement
-- that is too big.

local player = game:GetService("Players").LocalPlayer
if not player then
    return "wait-player"
end

local pg = player:FindFirstChild("PlayerGui")
if not pg then
    return "wait-gui"
end

local sg = game:GetService("StarterGui")
local opt = {}
opt.Title = "Wieen injected!"
opt.Text = "pwned by wieen! t.me/WieenExploit"
opt.Duration = 10
local ok = pcall(sg.SetCore, sg, "SendNotification", opt)
if not ok then
    return "wait"
end

print("pwned by wieen! t.me/WieenExploit")
return "ok"
