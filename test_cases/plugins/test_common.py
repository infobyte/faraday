def skip(self, n):
    for x in range(n):
        action = self.plugin._pending_actions.get(block=True)
