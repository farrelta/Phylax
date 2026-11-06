# Synthetic lab only. Production capture is separately managed by its owner.
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 10secs;
redef Log::default_rotation_dir = "/logs/finalized";
