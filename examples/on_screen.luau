-- Wieen: текст прямо в окне игры.
--
--   python3 src/cli/wieen.py run examples/on_screen.luau
--
-- В Android-клиенте Roblox нет консоли F9 (она есть только в десктопном),
-- поэтому print уходит в лог клиента. Этот скрипт вешает BillboardGui на
-- камеру — текст видно в игре. Правь строку TEXT под свой.
local TEXT = "wieen работает!"

local cam = workspace.CurrentCamera
if not cam then
    return "нет камеры"
end

local gui = Instance.new("BillboardGui")
gui.Name = "wieen"
gui.Size = UDim2.fromOffset(700, 140)
gui.StudsOffset = Vector3.new(0, 1.5, 0)
gui.AlwaysOnTop = true
gui.Parent = cam

local label = Instance.new("TextLabel")
label.Size = UDim2.fromScale(1, 1)
label.BackgroundTransparency = 1
label.TextColor3 = Color3.new(1, 0, 0)
label.TextStrokeTransparency = 0
label.Font = Enum.Font.GothamBold
label.TextSize = 40
label.Text = TEXT
label.Parent = gui

return "текст на экране: " .. TEXT
