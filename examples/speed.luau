-- Wieen: скорость персонажа (клиентская часть).
--
--   python3 src/cli/wieen.py run examples/speed.luau
--
-- Меняет WalkSpeed и JumpPower персонажа и закрепляет их в цикле
-- task-цикла игры: сервер Roblox шлёт своё значение WalkSpeed и без
-- закрепления оно сразу возвращается обратно.
local SPEED = 60
local JUMP = 120

local player = game:GetService("Players").LocalPlayer
local character = player.Character
if not character then
    return "персонажа нет (зайди в игру и повтори)"
end

local humanoid = character:FindFirstChildOfClass("Humanoid")
if not humanoid then
    return "у персонажа нет Humanoid"
end

humanoid.UseJumpPower = true
humanoid.WalkSpeed = SPEED
humanoid.JumpPower = JUMP

-- цикл живёт в планировщике самой игры, а не в нашем потоке
task.spawn(function()
    while true do
        humanoid.UseJumpPower = true
        humanoid.WalkSpeed = SPEED
        humanoid.JumpPower = JUMP
        task.wait(0.5)
    end
end)

return "скорость " .. tostring(humanoid.WalkSpeed) .. ", прыжок " .. tostring(humanoid.JumpPower)
