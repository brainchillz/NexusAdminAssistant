-- Skills gain a short description (the playbook body stays in `body`).
ALTER TABLE skills ADD COLUMN description TEXT DEFAULT '';
