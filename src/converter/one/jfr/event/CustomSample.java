/*
 * Copyright 2021 Andrei Pangin
 * Copyright 2022 Morgan Stanley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package one.jfr.event;

public class CustomSample extends Event {
    public final int index;
    public final String info;
    public final double value;

    public CustomSample(long time, int tid, int stackTraceId, int index, String info, double value) {
        super(time, tid, stackTraceId);
        this.index = index;
        this.value = value;
        this.info = info;
    }
}
